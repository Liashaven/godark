import Foundation
import Network
import UIKit
import BlackoutCore

/// Links to GoDark phones (iPhone or Android) on the same Wi-Fi network over TCP, found with Bonjour
/// (spec/FORMAT.md, "Wi-Fi networks"): a router with no internet, a hotspot, a community network or a rooftop link.
/// Only the phone with the smaller node id connects to a discovered phone; an address the user typed is always dialed.
/// The listener and the Bonjour browser start again after any failure, and when the app comes back to the foreground
/// (iOS may stop them while the app is suspended): the browser always, the listener unless it is still ready.
final class WifiLink {
    static let prefix = "wifi:"
    static let serviceType = "_darkproof._tcp"
    static let port: UInt16 = 7777
    static let maxFrame = 16_064
    static let maxLinks = 32
    private static let maxQueuedLink = 12 * 1024 * 1024 // waiting to go out to one phone; more means it stopped reading
    private static let maxQueuedAll = 32 * 1024 * 1024
    private var queued: [String: Int] = [:], queuedAll = 0 // on q
    private static let hello = Data("DPW1".utf8)
    private static let retryDelay = 5.0
    private static let helloWait = 10.0   // the other side's HELLO must come within this

    private let q = DispatchQueue(label: "wifi")
    private let nodeId: String
    private let router: MeshRouter
    private let onStatus: (String?) -> Void
    private var listener: NWListener?
    private var browser: NWBrowser?
    private var links: [String: (node: String, conn: NWConnection, dialed: Bool, since: Date)] = [:] // router peer id -> link
    private var byNode: [String: String] = [:]                              // node id -> router peer id
    private var found: [String: NWEndpoint] = [:]                           // discovered node id -> endpoint
    private var dialing = Set<String>()
    private var count = 0
    private var running = false
    private var manualTarget: (host: String, port: UInt16)?
    private var manualConn: NWConnection?
    private var manualGen = 0
    private var manualNode: String?        // who answered at the typed address last time
    private var note = ""
    private var listenGen = 0, browseGen = 0 // ignore state updates of a listener or browser already replaced
    private var listenRetry = 2.0, browseRetry = 2.0
    private var open: [ObjectIdentifier: NWConnection] = [:] // every connection from its start to its end, also before its HELLO
    private var waiting: [(conn: NWConnection, address: String)] = [] // connections that dialed in and haven't said HELLO yet, oldest first
    private var stopGen = 0                 // counts stop(): a connection begun before the last one never becomes a link
    private var rotatedAt = Date.distantPast
    /// The listener and the links to discovered phones never use the mobile network (spec "Wi-Fi networks").
    private static var lanOnly: NWParameters { let p = NWParameters.tcp; p.prohibitedInterfaceTypes = [.cellular]; return p }

    init(nodeId: String, router: MeshRouter, onStatus: @escaping (String?) -> Void) {
        self.nodeId = nodeId; self.router = router; self.onStatus = onStatus
        NotificationCenter.default.addObserver(forName: UIApplication.willEnterForegroundNotification, object: nil, queue: nil) { [weak self] _ in
            guard let self else { return }
            self.q.async {
                guard self.running else { return }
                // A listener that is still ready keeps its port (7777 would be busy for a moment after closing it).
                if let l = self.listener, case .ready = l.state {} else { self.listen(on: Self.port) }
                self.browse()
            }
        }
    }

    var nodes: Set<String> { q.sync { Set(byNode.keys) } }
    var listeningPort: UInt16? { q.sync { listener?.port?.rawValue } }
    var isOn: Bool { q.sync { running } }
    var manualAddress: String? { q.sync { manualTarget.map { "\($0.host):\($0.port)" } } }

    func start() {
        q.async {
            guard !self.running else { return }
            self.running = true
            self.listen(on: Self.port)
            self.browse()
            self.retryLoop()
            self.report()
        }
    }

    func stop() {
        q.async {
            self.running = false
            self.listenGen += 1; self.browseGen += 1; self.stopGen += 1
            self.listener?.cancel(); self.listener = nil
            self.browser?.cancel(); self.browser = nil
            self.found = [:]
            self.stopManualLocked()
            for (_, l) in self.links { l.conn.cancel() }
            for c in self.open.values { c.cancel() } // also the connections still being set up: none becomes a link afterwards
            self.waiting = []
            self.report()
        }
    }

    /// Keeps a link to an address the user typed, redialing every 5 s, until `stopManual()` or another address.
    func connect(host: String, port: UInt16) {
        q.async {
            self.stopManualLocked()
            self.manualTarget = (host, port); self.manualNode = nil
            self.dialManual(self.manualGen, host, port)
        }
    }

    func stopManual() { q.async { self.stopManualLocked(); self.report() } }

    private func stopManualLocked() {
        manualGen += 1; manualTarget = nil
        manualConn?.cancel(); manualConn = nil
    }

    /// Called by the router, possibly while it holds its lock: the write happens on this link's queue.
    func send(_ peer: String, _ p: Packet) {
        let b = p.encode()
        q.async {
            guard let l = self.links[peer] else { return }
            let n = b.count + 4
            // A phone that stopped reading: what is waiting for it would pile up here until iOS ended the app. When all
            // links together have too much waiting, the links that hold the most are closed, not the one this packet is
            // for: that one may be reading as it should.
            if self.queued[peer, default: 0] + n > Self.maxQueuedLink { self.cut(peer); return }
            while self.queuedAll + n > Self.maxQueuedAll, let top = self.queued.max(by: { $0.value < $1.value })?.key {
                self.cut(top)
                if top == peer { return }
            }
            self.queued[peer, default: 0] += n; self.queuedAll += n
            l.conn.send(content: Self.frame(b), completion: .contentProcessed { _ in
                self.q.async {
                    guard let have = self.queued[peer] else { return } // the link was cut: its bytes are off the total already
                    self.queuedAll -= n
                    self.queued[peer] = have > n ? have - n : nil
                }
            })
        }
    }

    /// Closes a link for what is waiting to go out to it. That no longer counts toward the total.
    private func cut(_ peer: String) {
        queuedAll -= queued.removeValue(forKey: peer) ?? 0
        if let l = links.removeValue(forKey: peer) { router.peerDown(peer); l.conn.cancel() }
    }

    // MARK: - Listening and discovery

    /// (Re)starts the listener on 7777, or on any free port if 7777 is taken. After any failure it starts again,
    /// later and later (2 s, then up to 30 s).
    private func listen(on port: UInt16) {
        guard running else { return }
        listenGen += 1
        let gen = listenGen
        listener?.cancel(); listener = nil
        let l: NWListener
        do { l = try NWListener(using: Self.lanOnly, on: NWEndpoint.Port(rawValue: port)!) }
        catch {
            guard port != 0, let any = try? NWListener(using: Self.lanOnly) else { note = "can't listen"; relisten(gen); return }
            l = any
        }
        l.service = NWListener.Service(name: nodeId, type: Self.serviceType)
        l.newConnectionHandler = { [weak self] c in
            guard let self, self.running else { c.cancel(); return }
            self.admit(c)
            self.run(c, dialed: false, local: true)
        }
        l.stateUpdateHandler = { [weak self] state in
            guard let self, gen == self.listenGen else { return }
            switch state {
            case .ready: self.listenRetry = 2; if self.note == "can't listen" { self.note = "" }
            case .failed:
                l.cancel(); self.listener = nil
                if port == Self.port { self.listen(on: 0) } else { self.relisten(gen) } // 7777 taken: any free port
            default: break
            }
        }
        l.start(queue: q)
        listener = l
    }

    private func relisten(_ gen: Int) {
        let wait = listenRetry; listenRetry = min(listenRetry * 2, 30)
        q.asyncAfter(deadline: .now() + wait) { [weak self] in
            guard let self, self.running, gen == self.listenGen else { return }
            self.listen(on: Self.port)
        }
    }

    /// (Re)starts the Bonjour browser; after a failure it starts again, later and later (2 s, then up to 30 s).
    private func browse() {
        guard running else { return }
        browseGen += 1
        let gen = browseGen
        browser?.cancel()
        let b = NWBrowser(for: .bonjour(type: Self.serviceType, domain: nil), using: .tcp)
        b.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self, gen == self.browseGen else { return }
            self.discovered(results)
        }
        b.stateUpdateHandler = { [weak self] state in
            guard let self, gen == self.browseGen else { return }
            switch state {
            case .ready: self.browseRetry = 2; self.setDenied(false)
            case .waiting(let e): // the user refused Local Network: Bonjour waits for ever
                if case .dns(let code) = e, code == -65570 { self.setDenied(true) } // kDNSServiceErr_PolicyDenied
            case .failed:
                b.cancel(); self.browser = nil
                let wait = self.browseRetry; self.browseRetry = min(self.browseRetry * 2, 30)
                self.q.asyncAfter(deadline: .now() + wait) { [weak self] in
                    guard let self, self.running, gen == self.browseGen else { return }
                    self.browse()
                }
            default: break
            }
        }
        b.start(queue: q)
        browser = b
    }

    /// A connection that dialed in waits for its HELLO. At most 16 wait, 4 of them from one address: over that, one
    /// that is still waiting gives way (that address's oldest, else the oldest of the address with the most, else the
    /// oldest of all), so connections that say nothing can't use up what the app may hold open.
    private func admit(_ c: NWConnection) {
        let a = Self.address(c.endpoint)
        switch LinkLimits.giveWay(waiting.map(\.address), address: a, max: LinkLimits.waiting, perAddress: LinkLimits.waitingPerAddress) {
        case .room: break
        case .full: waiting.removeFirst().conn.cancel()
        case .giveWay(let i): waiting.remove(at: i).conn.cancel()
        }
        waiting.append((c, a))
    }

    private func discovered(_ results: Set<NWBrowser.Result>) {
        var now: [String: NWEndpoint] = [:]
        for r in results where now.count < LinkLimits.found { // a device can announce any number of names: only so many are remembered
            if case let .service(name, _, _, _) = r.endpoint, name != nodeId { now[name] = r.endpoint }
        }
        found = now
        dialFound()
    }

    /// For deciding whether to dial `address` (`Self.address`): `node` counts as linked only through a link whose other
    /// end is that address. A node id in a HELLO proves nothing (spec/FORMAT.md, "Node ids prove nothing"), so a link
    /// from elsewhere that only claims a phone's id must not stop this phone from dialing the real one.
    private func linked(_ node: String, at address: String) -> Bool {
        links.values.contains { $0.node == node && Self.address($0.conn.endpoint) == address }
    }

    /// Only the smaller node id connects to a discovered phone (spec), once at a time, and only while it has no link
    /// to that phone's service: one from elsewhere may only claim its node id. At most 8 are dialed at once, in a new
    /// order each time, never over the mobile network, and only a phone on the local network gets a HELLO (`onLan`).
    private func dialFound() {
        guard running else { return }
        for (node, endpoint) in found.shuffled() where nodeId < node && !linked(node, at: Self.address(endpoint)) && !dialing.contains(node) {
            guard dialing.count < LinkLimits.dials else { break }
            dialing.insert(node)
            let c = NWConnection(to: endpoint, using: Self.lanOnly)
            run(c, dialed: true, local: true, ended: { [weak self] in self?.dialing.remove(node) })
        }
    }

    private func retryLoop() {
        q.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.running else { return }
            self.dialFound(); self.retryLoop()
        }
    }

    /// While the phone at that address is linked another way (it dialed this phone from that address), it isn't dialed
    /// again. A link from another address that claims its node id doesn't count.
    private func dialManual(_ g: Int, _ host: String, _ port: UInt16) {
        guard g == manualGen, let p = NWEndpoint.Port(rawValue: port) else { return }
        if let n = manualNode, linked(n, at: Self.address(.hostPort(host: NWEndpoint.Host(host), port: p))) {
            q.asyncAfter(deadline: .now() + Self.retryDelay) { [weak self] in self?.dialManual(g, host, port) }
            return
        }
        let c = NWConnection(host: NWEndpoint.Host(host), port: p, using: .tcp)
        manualConn = c
        run(c, dialed: true, failed: { [weak self] in self?.note = "can't reach \(host):\(port), retrying" },
            hello: { [weak self] node in if g == self?.manualGen { self?.manualNode = node } }) { [weak self] in
            guard let self, g == self.manualGen else { return }
            self.q.asyncAfter(deadline: .now() + Self.retryDelay) { self.dialManual(g, host, port) }
        }
        report()
    }

    // MARK: - One link

    /// Runs one connection: HELLO both ways, then packets. `dialed`: this phone opened it. `local`: the other end must
    /// be on the local network (every connection but one to an address the user typed). `hello` gets the other side's
    /// node id; `ended` runs once when the connection closes or fails.
    private func run(_ c: NWConnection, dialed: Bool, local: Bool = false, failed: (() -> Void)? = nil, hello: ((String) -> Void)? = nil,
                     ended: (() -> Void)? = nil) {
        var id: String?, linkNode: String?
        var finished = false
        let gen = stopGen
        open[ObjectIdentifier(c)] = c
        func finish() {
            guard !finished else { return }
            finished = true
            open[ObjectIdentifier(c)] = nil
            waiting.removeAll { $0.conn === c }
            if let id {
                links.removeValue(forKey: id)
                if let n = linkNode, byNode[n] == id { // unless a newer link replaced it
                    byNode.removeValue(forKey: n)
                    if let other = links.first(where: { $0.value.node == n }) { byNode[n] = other.key }
                }
                router.peerDown(id)
            }
            report()
            ended?()
        }
        c.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                // Stopped while this connection was being made, or its other end isn't on this network: no HELLO, no link.
                guard gen == self.stopGen, !local || self.onLan(c) else { c.cancel(); return }
                self.note = ""
                c.send(content: Self.frame(Self.hello + Data(self.nodeId.utf8)), completion: .contentProcessed { _ in })
                self.q.asyncAfter(deadline: .now() + Self.helloWait) { if id == nil && !finished { c.cancel() } } // no HELLO in time
                self.readHello(c) { node in
                    guard let node, node != self.nodeId, !finished, gen == self.stopGen else { c.cancel(); return }
                    self.waiting.removeAll { $0.conn === c }
                    hello?(node)
                    guard self.makeRoom(for: Self.host(c)) else { c.cancel(); return }
                    let now = Date()
                    var samePhone = true
                    if let old = self.byNode[node], let o = self.links[old] {
                        // Node ids aren't proof of anything: from another address this may be someone pretending, so the
                        // link that's there stays and this one runs beside it (the router sees each packet once).
                        samePhone = Self.address(o.conn.endpoint) == Self.address(c.endpoint)
                        if samePhone {
                            // spec "Restarts and duplicate links": both phones keep the same link
                            let ageMs = Int64(now.timeIntervalSince(o.since) * 1000)
                            guard DuplicateLinks.keepNew(myId: self.nodeId, remoteId: node, newDialedByMe: dialed,
                                                         oldDialedByMe: o.dialed, oldAgeMs: ageMs) else { c.cancel(); return }
                            o.conn.cancel()
                        }
                    }
                    self.count += 1
                    let peer = Self.prefix + node + "#" + String(self.count)
                    id = peer; linkNode = node
                    self.links[peer] = (node, c, dialed, now)
                    if samePhone { self.byNode[node] = peer }
                    // Every link from one address counts against one allowance in the router, however many node ids it sends.
                    self.router.peerUp(peer, sender: Self.prefix + "@" + Self.host(c))
                    self.report()
                    self.readFrames(c, peer)
                }
            case .waiting: failed?(); c.cancel() // e.g. refused: retry on our own schedule
            case .failed, .cancelled: finish()
            default: break
            }
        }
        c.start(queue: q)
    }

    /// Where a link's other end is: the host of an address (whatever the port: a phone that dials in comes from another
    /// one), or the whole endpoint for a phone found by Bonjour, whose address isn't known before it is dialed.
    private static func address(_ e: NWEndpoint) -> String {
        if case .hostPort(let host, _) = e { return "\(host)" }
        return "\(e)"
    }

    /// Where a connection's other end is, once it is connected: the address it reached (for a phone found by Bonjour
    /// too), as text.
    private static func host(_ c: NWConnection) -> String { address(c.currentPath?.remoteEndpoint ?? c.endpoint) }

    private static func bytes(_ e: NWEndpoint?) -> [UInt8]? {
        guard case .hostPort(let host, _)? = e else { return nil }
        switch host {
        case .ipv4(let a): return [UInt8](a.rawValue)
        case .ipv6(let a): return [UInt8](a.rawValue)
        default: return nil
        }
    }

    /// Whether a connection's other end is on a network this phone is on (spec "Wi-Fi networks": nothing leaves that
    /// network): a private or link-local address, or one in the same network as this phone's end of the connection
    /// (`LinkLimits.local`). Not another app on this phone, and not a host out on the internet, whatever a Bonjour
    /// answer says. An address that can't be read doesn't count.
    private func onLan(_ c: NWConnection) -> Bool {
        let path = c.currentPath
        guard let remote = Self.bytes(path?.remoteEndpoint ?? c.endpoint) else { return false }
        #if DEBUG
        // Debug builds also take loopback: the Simulator test (README) comes in that way.
        if remote == [127, 0, 0, 1] || remote == [UInt8](repeating: 0, count: 15) + [1] { return true }
        #endif
        return LinkLimits.local(remote, mine: Self.bytes(path?.localEndpoint))
    }

    /// A place for one more link from `address`. One address holds at most 8: its own oldest makes room. With every
    /// place taken, the address that holds the most gives up its oldest. If nobody holds more than one, a link at random
    /// gives way, at most once in 30 s and whatever its age, so nobody can hold every place: not by just staying, and
    /// not by making its links anew to keep them young.
    private func makeRoom(for address: String) -> Bool {
        let all = links.sorted { $0.value.since < $1.value.since }
        let gone: String
        switch LinkLimits.giveWay(all.map { Self.host($0.value.conn) }, address: address, max: Self.maxLinks, perAddress: LinkLimits.perAddress) {
        case .room: return true
        case .giveWay(let i): gone = all[i].key
        case .full:
            let now = Date()
            guard now.timeIntervalSince(rotatedAt) * 1000 >= Double(LinkLimits.rotateMs), let l = all.randomElement() else { return false }
            rotatedAt = now; gone = l.key
        }
        if let l = links.removeValue(forKey: gone) { router.peerDown(gone); l.conn.cancel() }
        return true
    }

    private func readHello(_ c: NWConnection, _ done: @escaping (String?) -> Void) {
        readFrame(c, max: Self.hello.count + 64) { body in
            guard let body, body.count > Self.hello.count, body.prefix(Self.hello.count) == Self.hello,
                  let node = String(data: body.dropFirst(Self.hello.count), encoding: .utf8) else { return done(nil) }
            done(node)
        }
    }

    private func readFrames(_ c: NWConnection, _ peer: String) {
        readFrame(c, max: Self.maxFrame) { [weak self] body in
            guard let self, let body else { c.cancel(); return }
            if let p = Packet.decode(body) { self.router.receive(from: peer, p) }
            self.readFrames(c, peer)
        }
    }

    /// One frame: a 4-byte big-endian length (1...max), then that many bytes. nil if the link broke or the length is wrong.
    private func readFrame(_ c: NWConnection, max: Int, _ done: @escaping (Data?) -> Void) {
        c.receive(minimumIncompleteLength: 4, maximumLength: 4) { head, _, _, error in
            guard let head, head.count == 4, error == nil else { return done(nil) }
            let n = head.reduce(0) { $0 << 8 | Int($1) }
            guard n >= 1, n <= max else { return done(nil) }
            c.receive(minimumIncompleteLength: n, maximumLength: n) { body, _, _, error in
                guard let body, body.count == n, error == nil else { return done(nil) }
                done(body)
            }
        }
    }

    private static func frame(_ b: Data) -> Data {
        Data([UInt8(b.count >> 24 & 0xFF), UInt8(b.count >> 16 & 0xFF), UInt8(b.count >> 8 & 0xFF), UInt8(b.count & 0xFF)]) + b
    }

    /// Whether iOS refused Local Network to GoDark (the Bonjour browser waits with "policy denied"). Any thread.
    var localNetworkDenied: Bool { deniedLock.lock(); defer { deniedLock.unlock() }; return _denied }
    private let deniedLock = NSLock()
    private var _denied = false
    private func setDenied(_ v: Bool) {
        deniedLock.lock(); let changed = _denied != v; _denied = v; deniedLock.unlock()
        if changed { note = v ? "Local Network not allowed" : ""; report() }
    }

    private func report() {
        guard running || manualTarget != nil else { onStatus(nil); return }
        var parts = ["\(links.count) link(s)"]
        if let m = manualTarget { parts.append("address \(m.host):\(m.port)") }
        if !note.isEmpty { parts.append(note) }
        onStatus("Wi-Fi network: " + parts.joined(separator: " · "))
    }
}
