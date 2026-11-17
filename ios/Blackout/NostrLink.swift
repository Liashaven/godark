import Foundation
import BlackoutCore

/// Links to public Nostr relays while there is internet (spec/FORMAT.md, "Internet relays"), like Android's NostrLink.
/// One peer for forwarding: the router gives it every packet and it hands the router what arrives for this phone's
/// mailboxes. Packets written on this phone go up first. Anyone else's (this phone bridging its neighbourhood) go up
/// only if no relay has them yet, and slowly, so the same packet isn't posted by every phone that holds it and relays
/// don't throttle us (RelayOutbox). Each group has its own connections, key and subscription (RelayScope), so one
/// connection never shows that two groups share a phone. Packets this phone only passes on go out with the Everyone
/// channel's, whatever mailbox their id names (`Nostr.scope`); a link set takes only packets of its own mailboxes
/// (`Nostr.takes`); and what came from the relays never goes back up (`MeshRouter.peerUp`, `FromRelays`). Scope links
/// are touched only on `q`, start and stop included, so a link that was stopped never gets a new link set.
final class NostrLink {
    static let peer = "nostr"
    /// Free public relays that stored a 22 KB event of this kind from a new key (tested 2026-11-06).
    static let relays = ["wss://nos.lol", "wss://relay.damus.io", "wss://relay.primal.net", "wss://nostr.mom", "wss://nostr.oxtr.dev", "wss://relay.ditto.pub"]
    /// Through Tor: nos.lol and nostr.mom don't answer Tor exits (tested 2026-11-06), so two others take their place.
    static let torRelays = ["wss://relay.damus.io", "wss://relay.primal.net", "wss://nostr.oxtr.dev", "wss://relay.ditto.pub", "wss://relay.nostr.net", "wss://nostr.data.haus"]
    #if DEBUG
    /// Launch arguments `relays ws://127.0.0.1:7447`: the mock relay in tools/mock-relay instead of the public ones.
    static var debugRelays: [String]?
    #endif

    /// One group's mailboxes; `id` is empty for the Everyone channel.
    struct Scope { let id: String; let mailboxes: [UInt16] }

    private let q = DispatchQueue(label: "nostr.scopes")
    private let router: MeshRouter
    private let scopes: () -> [Scope]
    private let onRelays: (String) -> Void
    private let packetKey: (String) -> String? // message id -> the packet this phone shows under it (MeshRouter.key), for reports
    private let fromRelays: FromRelays         // the packets relays brought first; Engine gives them to the router after a restart
    private let onStatus: (String?) -> Void
    private let boxLock = NSLock()
    private var boxes: [String: [UInt16]] = [:]   // guarded by boxLock: links read it on their own queues
    private var links: [String: RelayScope] = [:] // scope id -> its links
    private var running = false
    private var viaTor: Bool
    private var saver = false
    private var linksUp = 0                       // scopes with at least one relay linked

    init(router: MeshRouter, viaTor: Bool, scopes: @escaping () -> [Scope], packetKey: @escaping (String) -> String?,
         fromRelays: FromRelays, onRelays: @escaping (String) -> Void, onStatus: @escaping (String?) -> Void) {
        self.router = router; self.viaTor = Self.useTor(viaTor); self.scopes = scopes; self.packetKey = packetKey
        self.fromRelays = fromRelays; self.onRelays = onRelays; self.onStatus = onStatus
    }

    /// The mock relay of debug builds is on this computer: Tor couldn't reach it.
    private static func useTor(_ on: Bool) -> Bool {
        #if DEBUG
        if debugRelays != nil { return false }
        #endif
        return on
    }

    var isUp: Bool { q.sync { linksUp > 0 } }
    var connected: Int { q.sync { links.values.map(\.connected).max() ?? 0 } }
    var total: Int { Self.relays.count } // the Tor list is as long
    /// With "Connect through Tor": true while traffic is known to leave through Tor, false while waiting. Nil without.
    var throughTor: Bool? { q.sync { links[""]?.throughTor } }

    func start() { q.async { self.running = true; self.sync() } }

    func stop() {
        q.async {
            self.running = false
            self.links.values.forEach { $0.stop() }
            self.links = [:]
        }
    }

    func setSaver(_ on: Bool) { q.async { self.saver = on; self.links.values.forEach { $0.setSaver(on) } } }
    func setTor(_ on: Bool) { q.async { self.viaTor = Self.useTor(on); self.links.values.forEach { $0.setTor(Self.useTor(on)) } } }

    /// The groups or their keys changed: new groups get their own links, and each link whose mailboxes changed asks for them. Any thread.
    func resubscribe() { q.async { self.sync(); self.links.values.forEach { $0.resubscribe() } } }

    /// Called by the router: a packet written on this phone goes up on the links of its group, and anything else with
    /// the Everyone channel's (`Nostr.scope`). This phone's own wait a moment, at random, so the time a packet reaches
    /// a relay says less about when it was written. `mine`: this very packet was written here, not another one under
    /// its id. `from`: the link that brought it (`MeshRouter.source`), for its turn among the packets passed on
    /// (`RelayOutbox`).
    func send(_ p: Packet, mine: Bool, from: String = "") {
        q.asyncAfter(deadline: .now() + (mine ? Double.random(in: 0..<8) : 0)) {
            let id = Nostr.scope(p.id, mine: mine, boxes: self.boxLock.withLock { self.boxes })
            (self.links[id] ?? self.links[""])?.send(p, mine: mine, from: from)
        }
    }

    private func sync() {
        guard running else { return }
        var now: [Scope] = []
        for s in scopes() where !now.contains(where: { $0.id == s.id }) { now.append(s) }
        boxLock.withLock { boxes = Dictionary(uniqueKeysWithValues: now.map { ($0.id, $0.mailboxes) }) }
        for id in links.keys where !now.contains(where: { $0.id == id }) { links.removeValue(forKey: id)?.stop() }
        for s in now where links[s.id] == nil {
            let id = s.id
            let link = RelayScope(scope: id, router: router, viaTor: viaTor,
                                  mailboxes: { [weak self] in self.map { me in me.boxLock.withLock { me.boxes[id] ?? [] } } ?? [] },
                                  onUp: { [weak self] on in self?.scopeUp(on) }, onRelays: onRelays, packetKey: packetKey,
                                  fromRelays: fromRelays, onStatus: id.isEmpty ? onStatus : { _ in })
            link.setSaver(saver)
            links[id] = link
            link.start()
        }
    }

    /// The router sees one peer, up while any scope has a relay.
    private func scopeUp(_ on: Bool) {
        q.async {
            self.linksUp += on ? 1 : -1
            if on && self.linksUp == 1 { self.router.peerUp(Self.peer) }
            if !on && self.linksUp == 0 { self.router.peerDown(Self.peer) }
        }
    }
}

/// One group's links to the relays (or the Everyone channel's, when `scope` is empty): its own sockets, key and
/// subscription. All state is touched only on `q`.
final class RelayScope: NSObject, URLSessionWebSocketDelegate {
    private static let startSpread = 8.0    // groups link at different moments, so their connections don't line up
    private static let tick = 1.5           // at most one own packet per tick
    private static let bridgeEvery = 3      // and one bridged packet every 3 ticks
    private static let checkEvery = 10.0    // how often to ask relays which bridged packets they have
    private static let checkWait = 6.0      // how long to wait for their answers
    private static let checkBatch = 50
    private static let rest = 600.0         // pause posting to a relay that says to slow down
    private static let catchUpWait: Int64 = 20 // seconds: a catch-up REQ with no EOSE by then is given up on this link

    private let q = DispatchQueue(label: "nostr")
    private let router: MeshRouter
    private let scope: String
    private let saved: String    // the Everyone links keep the names older builds used
    private let key = NostrKey() // a new throwaway key every start and for each group: relays can't link them by key
    private let torUser = (0..<8).map { _ in String(format: "%02x", UInt8.random(in: .min ... .max)) }.joined() // its own Tor circuits
    private let mailboxes: () -> [UInt16]
    private let onUp: (Bool) -> Void
    private let onStatus: (String?) -> Void
    private var session: URLSession!       // direct
    private var torSession: URLSession?    // through the app's own Tor (InAppTor), once it has a circuit
    private var tasks: [String: URLSessionWebSocketTask] = [:]   // url -> socket
    private var open = Set<String>()
    private var backoff: [String: Double] = [:]
    private var resting: [String: Date] = [:]                     // relay -> post again after
    private let outbox: RelayOutbox
    private let since: RelaySince
    private var catchUps: [String: CatchUp] = [:]                  // relay -> its catch-up
    private var paces: [String: RelayPace] = [:]                   // relay -> what it sent this minute
    private let subjects = ReportSubjects()                        // the relay events that carried Public packets, for reports
    private var shown: [String: String] = [:]                      // reported message id -> the packet shown under it ("" if none)
    private var running = false
    private var up = false
    private var checking = false
    private var ticks = 0
    private var live = Nostr.subId("live") // random: an id made from the clock would be almost the same on every link set of this phone
    private var subscribed: [String: [UInt16]] = [:]               // relay -> the mailboxes its live subscription asks for
    private var lookup = Set<String>()                             // the packet ids of the #x lookup in flight
    private var timers: [DispatchSourceTimer] = []
    private var viaTor: Bool
    private var torOK: Bool?            // with Tor: whether the check said traffic leaves through Tor; nil without
    private var torChecking = false
    private var saver = false           // "Battery saver": lookups 4× less often, bridged packets more slowly

    private let onRelays: (String) -> Void // a packet went up to the relays, or they had it already
    private let packetKey: (String) -> String? // message id -> the packet this phone shows under it (MeshRouter.key)
    private let fromRelays: FromRelays         // the packets relays brought first: they never go back up, after a restart either

    init(scope: String, router: MeshRouter, viaTor: Bool, mailboxes: @escaping () -> [UInt16], onUp: @escaping (Bool) -> Void,
         onRelays: @escaping (String) -> Void, packetKey: @escaping (String) -> String?, fromRelays: FromRelays,
         onStatus: @escaping (String?) -> Void) {
        self.scope = scope; self.router = router; self.viaTor = viaTor; self.mailboxes = mailboxes
        self.onUp = onUp; self.onRelays = onRelays; self.packetKey = packetKey; self.fromRelays = fromRelays; self.onStatus = onStatus
        saved = scope.isEmpty ? "" : ".\(scope)"
        outbox = RelayOutbox(sent: UserDefaults.standard.stringArray(forKey: "relaySent\(saved)") ?? [])
        since = RelaySince(UserDefaults.standard.string(forKey: "relaySince\(saved)") ?? "")
        torOK = viaTor ? false : nil
        super.init()
        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = false
        session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }

    var isUp: Bool { q.sync { up } }
    var connected: Int { q.sync { open.count } }
    #if DEBUG
    private var relays: [String] { NostrLink.debugRelays ?? (viaTor ? NostrLink.torRelays : NostrLink.relays) }
    #else
    private var relays: [String] { viaTor ? NostrLink.torRelays : NostrLink.relays }
    #endif
    /// With "Connect through Tor": true while traffic is known to leave through Tor, false while waiting. Nil without.
    var throughTor: Bool? { q.sync { torOK } }

    func start() { q.async { self.startNow() } }
    func stop() { q.async { self.stopNow() } }

    /// "Battery saver" on or off: the phone's own messages still go up at once; lookups for bridged packets come every
    /// 40 s instead of 10, bridged packets go up every 8 ticks instead of 3, and lost relays are retried less often.
    func setSaver(_ on: Bool) {
        q.async {
            guard self.saver != on else { return }
            self.saver = on
            guard self.running else { return }
            self.timers.forEach { $0.cancel() }
            self.timers = self.makeTimers()
        }
    }

    private func makeTimers() -> [DispatchSourceTimer] {
        [every(Self.tick) { $0.pump() }, every(saver ? Self.checkEvery * 4 : Self.checkEvery) { $0.check() }]
    }

    /// Turns "Connect through Tor" on or off: drops every relay link and links again.
    func setTor(_ on: Bool) {
        q.async {
            let was = self.running
            self.stopNow()
            self.viaTor = on; self.torOK = on ? false : nil
            if was { self.startNow() } else { self.report() }
        }
    }

    private func startNow() {
        guard !running else { return }
        running = true
        q.asyncAfter(deadline: .now() + (scope.isEmpty ? 0 : Double.random(in: 0..<Self.startSpread))) { [weak self] in
            guard let self, self.running else { return }
            self.relays.forEach(self.connect)
        }
        timers = makeTimers()
        report()
    }

    private func stopNow() {
        running = false
        timers.forEach { $0.cancel() }; timers = []
        tasks.values.forEach { $0.cancel(with: .goingAway, reason: nil) }
        tasks = [:]; open = []; catchUps = [:]; subscribed = [:]
        if up { up = false; onUp(false) }
        save()
        report()
    }

    private func every(_ s: Double, _ f: @escaping (RelayScope) -> Void) -> DispatchSourceTimer {
        let t = DispatchSource.makeTimerSource(queue: q)
        t.schedule(deadline: .now() + s, repeating: s)
        t.setEventHandler { [weak self] in if let self { f(self) } }
        t.resume()
        return t
    }

    /// The groups changed: if this link set's mailboxes did, every relay gets the new live subscription and catches up
    /// the new mailboxes. A link set whose mailboxes are the same sends nothing, so a change in one group doesn't show
    /// on the links of all the others at the same moment. Any thread.
    func resubscribe() {
        q.async {
            let boxes = self.mailboxes()
            guard self.open.contains(where: { self.subscribed[$0] != boxes }) else { return }
            let old = self.live
            self.live = Nostr.subId("live")
            for url in self.open {
                self.tasks[url]?.send(.string(Nostr.close(old))) { _ in }
                self.tasks[url]?.send(.string(Nostr.live(self.live, mailboxes: boxes))) { _ in }
                self.subscribed[url] = boxes
                self.catchUps[url]?.add(boxes)
                if let r = self.catchUps[url]?.next(now: Self.nowS()) { self.tasks[url]?.send(.string(r.text)) { _ in } }
            }
        }
    }

    /// Called by the router: queues the packet unless it came from the relays, is on them already or is too old.
    /// `mine` = written on this phone (a message or a receipt). Older own packets may be on the relays already (the
    /// app can be killed before it saves what it posted), so they are looked up first, like anyone else's.
    func send(_ p: Packet, mine: Bool, from: String = "") { q.async { self.outbox.offer(p, mine: mine, from: from) } }

    // MARK: - Tor

    /// Waits for the app's own Tor, then asks the Tor Project through it whether traffic leaves through Tor; links to
    /// the relays if so, else tries again soon.
    private func checkTor() {
        guard running, !torChecking else { return }
        guard let conf = InAppTor.shared.sessionConfiguration(user: torUser) else { // Tor is still starting
            q.asyncAfter(deadline: .now() + 2) { [weak self] in self?.checkTor() }
            return
        }
        if torSession == nil {
            conf.waitsForConnectivity = false
            torSession = URLSession(configuration: conf, delegate: self, delegateQueue: nil)
        }
        guard let s = torSession else { return }
        torChecking = true
        var r = URLRequest(url: TorCheck.url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        r.httpShouldHandleCookies = false
        s.dataTask(with: r) { [weak self] data, _, _ in
            guard let self else { return }
            self.q.async {
                self.torChecking = false
                guard self.running, self.viaTor else { return }
                let ok = data.map(TorCheck.isTor) ?? false
                #if DEBUG
                let exit = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["IP"] as? String
                DebugLog.write("tor check \(self.scope.isEmpty ? "everyone" : String(self.scope.prefix(6))): \(exit ?? "?")")
                #endif
                self.torOK = ok
                if ok { self.relays.forEach(self.connect) }
                else { self.q.asyncAfter(deadline: .now() + 5) { [weak self] in self?.checkTor() } } // Tor may still be starting
                self.report()
            }
        }.resume()
    }

    // MARK: - Sockets

    private func connect(_ url: String) {
        guard running, let u = URL(string: url), tasks[url] == nil else { return }
        if viaTor && torOK != true { checkTor(); return } // with Tor: only after the check, and only through it
        guard let s = viaTor ? torSession : session else { return }
        let t = s.webSocketTask(with: u)
        t.maximumMessageSize = 1 << 20
        tasks[url] = t
        t.resume()
        receive(url, t)
    }

    func urlSession(_ s: URLSession, webSocketTask t: URLSessionWebSocketTask, didOpenWithProtocol p: String?) {
        q.async {
            guard let url = self.tasks.first(where: { $0.value === t })?.key else { return }
            self.open.insert(url); self.backoff[url] = nil
            #if DEBUG
            DebugLog.write("relay open \(url.replacingOccurrences(of: "wss://", with: "")) \(self.scope.isEmpty ? "everyone" : String(self.scope.prefix(6)))")
            #endif
            let boxes = self.mailboxes()
            t.send(.string(Nostr.live(self.live, mailboxes: boxes))) { _ in }
            self.subscribed[url] = boxes
            let pace = self.paces[url] ?? RelayPace()
            self.paces[url] = pace
            let cu = CatchUp(relay: url, since: self.since, pace: pace)
            cu.add(boxes)
            self.catchUps[url] = cu
            if let r = cu.next(now: Self.nowS()) { t.send(.string(r.text)) { _ in } }
            if !self.up { self.up = true; self.onUp(true) } // the router then offers every stored packet
            self.report()
        }
    }

    private func receive(_ url: String, _ t: URLSessionWebSocketTask) {
        t.receive { [weak self] result in
            guard let self else { return }
            self.q.async {
                guard self.tasks[url] === t else { return }
                switch result {
                case .failure: self.lost(url, t)
                case .success(let m):
                    if case .string(let text) = m { self.handle(url, text) }
                    self.receive(url, t)
                }
            }
        }
    }

    private func handle(_ url: String, _ text: String) {
        if let ok = Nostr.ok(text) {
            if !ok.accepted {
                #if DEBUG
                DebugLog.write("relay \(url) refused an event: \(ok.reason.prefix(150))")
                #endif
                if Nostr.isThrottle(ok.reason) { resting[url] = Date().addingTimeInterval(Self.rest) }
            }
            if let id = outbox.answer(relay: url, ok) { onRelays(id) } // "Sent" only once a relay took it
            return
        }
        if let e = Nostr.end(text) {
            if let r = catchUps[url]?.end(e.subId, complete: e.complete, now: Self.nowS()) { tasks[url]?.send(.string(r.text)) { _ in } } // older page or next mailbox
            return
        }
        // No catch-up, no share of the relay's limit: nothing is taken without being counted.
        guard let cu = catchUps[url], cu.allow(now: Self.nowS()) else { return }
        cu.frame(text) // every event of a catch-up page counts, also one that carries no packet or isn't taken
        guard let r = Nostr.received(text) else { return }
        // Only this link set's own mailboxes, or what its lookup asked for: a relay can't plant anything else here.
        guard Nostr.takes(r.packet, mailboxes: mailboxes(), asked: lookup) else { return }
        subjects.note(relay: url, r)
        if r.subId == live { cu.live(Packet.mailbox(of: r.packet.id), createdAt: r.createdAt, now: Self.nowS()) }
        if let id = outbox.fromRelay(r) { onRelays(id) } // a copy the packet's recipients don't get isn't "on the relays"
        // Also answers to the #x lookups: the router ignores packets it already has. One that is new came from the
        // relays: it never goes back up, after a restart either.
        if router.receive(from: NostrLink.peer, r.packet) { fromRelays.add(r.packet) }
    }

    private func lost(_ url: String, _ t: URLSessionWebSocketTask) {
        guard tasks[url] === t else { return }
        tasks[url] = nil; open.remove(url); catchUps[url] = nil; subscribed[url] = nil
        if open.isEmpty && up { up = false; onUp(false) }
        if open.isEmpty && torOK == true { torOK = false } // Tor may have lost its circuits: check again before linking
        report()
        guard running else { return }
        let wait = min((backoff[url] ?? 2.5) * 2, saver ? 480 : 120) // no internet: try again, less and less often
        backoff[url] = wait
        q.asyncAfter(deadline: .now() + wait) { [weak self] in self?.connect(url) }
    }

    // MARK: - Posting

    /// Every tick: one own packet, else (every few ticks) one bridged packet no relay had, else pending reports. Only
    /// to relays that aren't resting; with none, packets stay queued.
    private func pump() {
        guard running else { return }
        ticks += 1
        outbox.expire() // posts no relay accepted in time go back in the queue
        let now = Date()
        let ready = open.filter { (resting[$0] ?? .distantPast) < now }
        if !ready.isEmpty {
            if let n = outbox.next(bridged: ticks % (saver ? 8 : Self.bridgeEvery) == 0) { post(n.packet, fromOwn: n.fromOwn, to: ready) }
            else { sendReports() }
        }
        save()
    }

    private func post(_ p: Packet, fromOwn: Bool, to relays: Set<String>) {
        let e = Nostr.event(p, pubkey: key.pubkey, now: Nostr.blurred(Self.nowS()), sign: key.sign)
        let msg = Nostr.publish(e)
        for url in relays { tasks[url]?.send(.string(msg)) { _ in } }
        outbox.posted(eventId: e["id"] as? String ?? "", p, fromOwn: fromOwn, relays: relays)
    }

    /// The sent list, the catch-up starts and what came from the relays, when they changed.
    private func save() {
        if outbox.changed { UserDefaults.standard.set(outbox.sentList(), forKey: "relaySent\(saved)") }
        if since.changed { UserDefaults.standard.set(since.save(), forKey: "relaySince\(saved)") }
        if fromRelays.changed { UserDefaults.standard.set(fromRelays.save(), forKey: FromRelays.pref) }
    }

    /// Asks the relays which of the newest unchecked bridged packets they have; the rest get posted. Also ends stuck
    /// catch-ups.
    private func check() {
        guard running else { return }
        catchUpTimeouts()
        guard !checking, !open.isEmpty else { return }
        let batch = outbox.toCheck(Self.checkBatch)
        guard !batch.isEmpty else { return }
        checking = true
        let subId = Nostr.subId("have")
        lookup = Set(batch.map(\.id)) // answers to it are taken whatever their mailbox (Nostr.takes)
        let req = Nostr.have(subId, packetIds: batch.map(\.id))
        for url in open { tasks[url]?.send(.string(req)) { _ in } }
        q.asyncAfter(deadline: .now() + Self.checkWait) { [weak self] in
            guard let self else { return }
            for url in self.open { self.tasks[url]?.send(.string(Nostr.close(subId))) { _ in } }
            for id in self.outbox.checked(batch) { self.onRelays(id) } // only copies with the same contents count (Nostr.digest), in an event the recipients get
            self.lookup = []; self.checking = false
        }
    }

    private func catchUpTimeouts() {
        let now = Self.nowS()
        for (url, cu) in catchUps {
            guard let c = cu.current, now - cu.sentAt >= Self.catchUpWait else { continue }
            tasks[url]?.send(.string(Nostr.close(c.subId))) { _ in }
            if let r = cu.end(c.subId, complete: false, now: now) { tasks[url]?.send(.string(r.text)) { _ in } }
        }
    }

    private static func nowS() -> Int64 { Int64(Date().timeIntervalSince1970) }

    private func sendReports() {
        var done: [String] = []
        for id in Moderation.pendingReports {
            guard subjects.knows(id) else { continue } // only messages that came from relays can be reported there
            if shown[id] == nil { if shown.count >= 200 { shown.removeAll() }; shown[id] = packetKey(id) ?? "" } // reads the store: once per message
            // Named: an event that carried the very packet this phone shows, and that its author signed. Else the report waits.
            guard let e = subjects.of(shown[id] ?? "") else { continue }
            let msg = Nostr.publish(Nostr.report(eventId: e.eventId, author: e.pubkey, pubkey: key.pubkey, sign: key.sign))
            for url in open { tasks[url]?.send(.string(msg)) { _ in } }
            done.append(id)
        }
        if !done.isEmpty { DispatchQueue.main.async { Moderation.reportsSent(done) } }
    }

    private func report() {
        guard running else { return onStatus(nil) }
        onStatus(torOK == false ? "Internet: waiting for Tor"
                 : "Internet: \(open.count) of \(relays.count) relays" + (torOK == true ? " through Tor" : ""))
    }
}
