import XCTest
@testable import BlackoutCore

/// What a relay or a neighbour could learn about which groups a phone is in (audit of 2026-11). Each of these failed
/// before its fix; Android's RelayLinksTest checks the same (and, there only, two races the iPhone never had: its relay
/// links start, stop and resubscribe on one queue, and it keeps one socket for each relay). Dummy packets and mailboxes only.
///
/// NostrLink and RelayScope are in the app, with its sockets, so the tests run the rules they are made of
/// (`Nostr.subId`, `Nostr.takes`, `Nostr.scope`, `MeshRouter`, `FromRelays`); `Phone` wires them the way RelayScope's
/// message handler, NostrLink.send and Engine.route do.
final class RelayLinksTests: XCTestCase {
    private static let relays = "nostr" // NostrLink.peer
    private let now = Int64(Date().timeIntervalSince1970 * 1000)
    private let groupOne: UInt16 = 0x6a44, groupTwo: UInt16 = 0x1b2c
    private var scopes: [String: [UInt16]] { ["group-one": [groupOne], "group-two": [groupTwo], "": [Nostr.publicMailbox]] }
    /// 98 junk bytes with two hops left: the phone that gets it offers it on once, and no phone after it.
    private func junk(_ id: String, _ fill: UInt8, ts: Int64? = nil) -> Packet {
        Packet(id: id, ts: ts ?? now, ttl: 2, cipher: Data(repeating: fill, count: MeshRouter.minSealed))
    }

    private final class Phone {
        let boxes: [String: [UInt16]]
        var delivered: [String] = []
        var toRelays: [String] = []      // what the router offered the relay peer
        var mine = Set<String>()         // ids of packets written on this phone
        let fromRelays: FromRelays
        var outbox: [String: RelayOutbox] = [:] // one for each link set
        var router: MeshRouter!

        init(_ boxes: [String: [UInt16]], saved: String = "", restored: [Packet] = []) {
            self.boxes = boxes
            fromRelays = FromRelays(saved)
            for id in boxes.keys { outbox[id] = RelayOutbox(jitter: { 0 }) }
            router = MeshRouter(send: { [unowned self] peer, p in
                guard peer == RelayLinksTests.relays else { return }
                self.toRelays.append(p.id)
                let own = self.mine.contains(p.id)
                self.outbox[Nostr.scope(p.id, mine: own, boxes: self.boxes)]!.offer(p, mine: own)
            }, deliver: { [unowned self] p in self.delivered.append(p.id) }, minCipher: MeshRouter.minSealed)
            let brought = fromRelays
            router.restore(restored, seenIds: Set(restored.map(MeshRouter.key)), from: { brought.contains($0) ? RelayLinksTests.relays : "" })
        }

        /// A relay sends `p` on a link of `scope`'s link set, while that set's lookup names `asked`.
        func relaySends(_ scope: String, _ p: Packet, asked: Set<String> = []) {
            guard Nostr.takes(p, mailboxes: boxes[scope]!, asked: asked) else { return }
            if router.receive(from: RelayLinksTests.relays, p) { fromRelays.add(p) }
        }
        var queued: [String: Int] { outbox.mapValues { $0.queued } }
    }

    // MARK: - The subscription id

    // The ids were the phone's clock in base 36: on the links of one phone they were a moment apart.
    func testASubscriptionIdSaysNothingAboutThePhoneOrItsOtherLinkSets() {
        let ids = (1...50).map { _ in Nostr.subId("live") }
        XCTAssertTrue(ids.allSatisfy { $0.hasPrefix("live") && $0.count == 4 + 16 })
        let values = ids.compactMap { UInt64($0.dropFirst(4), radix: 16) }.sorted()
        XCTAssertEqual(Set(values).count, 50)
        // Ids made one after another, as NostrLink.resubscribe makes them for every link set, are nowhere near each other.
        XCTAssertTrue(zip(values, values.dropFirst()).allSatisfy { $1 - $0 > 1 << 32 })
        // Read the way the audit read them, as a base 36 number, none is this phone's clock.
        let clock = Int64(Date().timeIntervalSince1970 * 1000)
        for id in ids + [Nostr.subId("have")] {
            guard let v = Int64(id.dropFirst(4), radix: 36) else { continue }
            XCTAssertGreaterThan(abs(v - clock), 3_600_000)
        }
        XCTAssertNotEqual(Nostr.subId("have"), Nostr.subId("have"))
    }

    // MARK: - What a link set takes

    func testALinkSetTakesOnlyPacketsOfItsOwnMailboxesAndAnswersToItsLookup() {
        let own = junk("6a4400000000c001", 1), other = junk("1b2c00000000c002", 2), foreign = junk("beef00000000c003", 3)
        XCTAssertTrue(Nostr.takes(own, mailboxes: [groupOne], asked: []))
        XCTAssertFalse(Nostr.takes(other, mailboxes: [groupOne], asked: []))   // another group of this phone
        XCTAssertFalse(Nostr.takes(foreign, mailboxes: [groupOne], asked: [])) // nobody's here
        XCTAssertFalse(Nostr.takes(own, mailboxes: [Nostr.publicMailbox], asked: []))
        XCTAssertTrue(Nostr.takes(foreign, mailboxes: [Nostr.publicMailbox], asked: [foreign.id])) // the Everyone links asked for it
        XCTAssertFalse(Nostr.takes(foreign, mailboxes: [Nostr.publicMailbox], asked: [other.id]))
    }

    // A relay sent junk on group one's link; after the links came back it was looked up and posted on the Everyone
    // links, or on group two's when its id began with group two's mailbox. The relay then knew all three were one phone.
    func testWhatARelaySendsOnOneGroupsLinkIsNeverNamedOnAnotherLinkSet() {
        let phone = Phone(scopes)
        phone.router.peerUp(Self.relays)
        let a = junk("beef00000000c301", 0x41) // mailbox beef: none of this phone's
        let b = junk("1b2c00000000c302", 0x42) // mailbox 1b2c: group two's
        let c = junk("6a4400000000c304", 0x44) // group one's own mailbox: this one the link takes
        for p in [a, b, c] { phone.relaySends("group-one", p) }
        XCTAssertEqual(phone.delivered, [c.id])
        phone.router.peerDown(Self.relays); phone.router.peerUp(Self.relays) // every relay link lost, then one is back
        XCTAssertEqual(phone.toRelays, [])
        XCTAssertEqual(phone.queued, ["group-one": 0, "group-two": 0, "": 0])
    }

    // The phone gave its newest stored packets back to the router at start with no word on where they came from, and
    // the router offered all of them to the relays.
    func testAfterARestartWhatTheRelaysBroughtStillDoesntGoBackUp() {
        let first = Phone(scopes)
        first.router.peerUp(Self.relays)
        let one = junk("6a4400000000c305", 0x45), two = junk("1b2c00000000c306", 0x46), all = junk("957600000000c307", 0x47)
        first.relaySends("group-one", one); first.relaySends("group-two", two); first.relaySends("", all)
        let neighbours = junk("beef00000000c308", 0x48)
        first.router.receive(from: "ble:neighbour", neighbours)
        XCTAssertEqual(first.delivered, [one.id, two.id, all.id, neighbours.id])
        let stored = [one, two, all, neighbours]

        let second = Phone(scopes, saved: first.fromRelays.save(), restored: stored) // the restart
        XCTAssertEqual(second.delivered, [])                                         // nothing is shown twice
        second.router.peerUp(Self.relays)
        XCTAssertEqual(second.toRelays, [neighbours.id]) // bridging goes on; what the relays sent is named on no link
        XCTAssertEqual(second.queued, ["group-one": 0, "group-two": 0, "": 1])

        // A phone that kept nothing about where its packets came from bridges them all, as before: nothing else holds them back.
        let forgot = Phone(scopes, restored: stored)
        forgot.router.peerUp(Self.relays)
        XCTAssertEqual(Set(forgot.toRelays), Set(stored.map(\.id)))
    }

    func testWhatCameFromTheRelaysIsRememberedByPacketTimeSoAFloodCantPushItOut() {
        let f = FromRelays(max: 3)
        let kept = (1...3).map { junk(String(format: "6a44%012x", $0), UInt8($0), ts: now + Int64($0)) }
        kept.forEach(f.add)
        XCTAssertTrue(f.changed)
        // After a restart the phone passes on its newest packets. Any number of older ones doesn't push those out of here.
        for i in 0..<200 { f.add(junk(String(format: "6a44%012x", 1000 + i), UInt8(i), ts: now - 1000 - Int64(i))) }
        XCTAssertEqual(f.count, 3); XCTAssertTrue(kept.allSatisfy { f.contains(MeshRouter.key($0)) })
        f.add(junk("6a440000000000ff", 9, ts: now + 10)) // a newer one takes the place of the oldest
        XCTAssertFalse(f.contains(MeshRouter.key(kept[0]))); XCTAssertTrue(f.contains(MeshRouter.key(kept[2])))
        let again = FromRelays(f.save(), max: 3)
        XCTAssertFalse(again.changed); XCTAssertEqual(again.count, 3); XCTAssertTrue(again.contains(MeshRouter.key(kept[1])))
        let squatter = Packet(id: kept[1].id, ts: kept[1].ts, ttl: 2, cipher: Data(repeating: 0x7f, count: 98))
        XCTAssertFalse(again.contains(MeshRouter.key(squatter))) // junk under its id is another packet
        XCTAssertEqual(FromRelays("nonsense,=5,x=y,").count, 0)
    }

    // MARK: - Which link set a packet goes up on

    // The link set was picked by the first 2 bytes of the packet id, which its sender chooses: a neighbour's junk that
    // began with a group's mailbox was posted with that group's key, the key of the phone's own messages there.
    func testANeighboursPacketGoesUpWithTheEveryoneLinksWhateverMailboxItNames() {
        let boxes: [String: [UInt16]] = ["group-one": [groupOne], "": [Nostr.publicMailbox]]
        XCTAssertEqual(Nostr.scope("6a4400000000c201", mine: false, boxes: boxes), "")
        XCTAssertEqual(Nostr.scope("beef00000000c202", mine: false, boxes: boxes), "")
        XCTAssertEqual(Nostr.scope("6a4400000000c203", mine: true, boxes: boxes), "group-one") // this phone's own
        XCTAssertEqual(Nostr.scope("957600000000c204", mine: true, boxes: boxes), "")          // its own Everyone message
        XCTAssertEqual(Nostr.scope("beef00000000c205", mine: true, boxes: boxes), "")

        let phone = Phone(boxes)
        phone.router.peerUp(Self.relays); phone.router.peerUp("wifi:neighbour")
        let test = junk("6a4400000000c201", 0x51)    // begins with the mailbox of the phone's group
        let control = junk("beef00000000c202", 0x52) // a mailbox the phone doesn't have
        phone.router.receive(from: "wifi:neighbour", test); phone.router.receive(from: "wifi:neighbour", control)
        let own = Packet(id: "6a4400000000c203", ts: now, ttl: 16, cipher: Data(repeating: 0x53, count: MeshRouter.minSealed))
        phone.mine.insert(own.id); phone.router.publish(own)
        XCTAssertEqual(phone.toRelays, [test.id, control.id, own.id]) // all three still go up: bridging works
        // Both of the neighbour's packets wait on the Everyone links, so they go up under one key, like on a phone without the group.
        XCTAssertEqual(Set(phone.outbox[""]!.toCheck(50).map(\.id)), [test.id, control.id])
        // The group's links carry only what this phone wrote there.
        let groups = phone.outbox["group-one"]!
        XCTAssertEqual(groups.queued, 1); XCTAssertEqual(groups.next(bridged: true)?.packet.id, own.id)
        XCTAssertEqual(groups.queued, 0)
    }

    // MARK: - The router: nothing goes back to the link that brought it

    func testALinkThatComesBackDoesntGetWhatItBroughtButEveryOtherLinkDoes() {
        var sent: [String] = []
        let t = now
        let r = MeshRouter(send: { peer, p in sent.append("\(peer) \(p.id) ttl \(p.ttl)") }, deliver: { _ in }, now: { t })
        let p = junk("6a4400000000c401", 1)
        r.peerUp(Self.relays)
        XCTAssertTrue(r.receive(from: Self.relays, p)); XCTAssertFalse(r.receive(from: Self.relays, p)) // new only once
        r.peerDown(Self.relays); r.peerUp(Self.relays)
        XCTAssertEqual(sent, [])
        r.peerUp("ble:a")
        XCTAssertEqual(sent, ["ble:a \(p.id) ttl 1"])
        // Restored as brought by the relays: the same.
        sent = []
        let again = MeshRouter(send: { peer, p in sent.append("\(peer) \(p.id) ttl \(p.ttl)") }, deliver: { _ in }, now: { t })
        again.peerUp(Self.relays)
        again.restore([p], seenIds: [MeshRouter.key(p)], from: { _ in Self.relays })
        again.peerDown(Self.relays); again.peerUp(Self.relays); again.peerUp("ble:a")
        XCTAssertEqual(sent, ["ble:a \(p.id) ttl 1"])
    }

    // What comes back after a restart is the newest packets, whoever brought them. If knowing that a relay brought a
    // packet made it go first, like the packets of a link that holds too many, an older relay packet that a flood had
    // pushed out of `FromRelays` would stay instead, with nothing to say it came from a relay, and go back up.
    func testAfterARestartTheNewestPacketsComeBackWhoeverBroughtThem() {
        var sent: [String] = []
        let t = now
        let r = MeshRouter(send: { peer, p in sent.append("\(peer) \(p.id)") }, deliver: { _ in }, now: { t }, maxStored: 4)
        let old = (1...2).map { junk(String(format: "6a44%012x", $0), UInt8($0), ts: now - 10_000 + Int64($0)) }      // forgotten: no word on who brought them
        let newer = (1...4).map { junk(String(format: "6a44%012x", 100 + $0), UInt8($0), ts: now - 1_000 + Int64($0)) } // known to be from the relays
        let relayed = Set(newer.map(MeshRouter.key))
        r.restore(old + newer, from: { relayed.contains($0) ? Self.relays : "" })
        r.peerUp(Self.relays)
        XCTAssertEqual(sent, [])
        r.peerUp("ble:a")
        XCTAssertEqual(sent, newer.map { "ble:a \($0.id)" })
        r.receive(from: "ble:b", old[0]); XCTAssertEqual(sent.count, 4) // the older ones were still marked as seen: not taken as new
    }

    // The first copy's ttl still doesn't decide how far a packet goes: a copy another link brought with more hops left
    // goes to the first link as well, when it comes back.
    func testACopyWithMoreHopsFromAnotherLinkGoesToTheFirstLinkToo() {
        var sent: [String] = []
        let t = now
        let r = MeshRouter(send: { peer, p in sent.append("\(peer) \(p.id) ttl \(p.ttl)") }, deliver: { _ in }, now: { t })
        let p = junk("6a4400000000c402", 2)
        r.receive(from: "ble:a", p); r.peerDown("ble:a")
        XCTAssertFalse(r.receive(from: "ble:b", p.withTtl(10)))
        r.peerUp("ble:a")
        XCTAssertEqual(sent, ["ble:a \(p.id) ttl 9"])
    }

    // Android's Wi-Fi board posts were published like the phone's own packets, which count against no link's share: 500
    // of them pushed every packet the phone held for others out of the store. The iPhone has no board; its router keeps
    // the same rule as Android's.
    func testPacketsPublishedForOthersCountAsOneLinksShare() {
        var sent = Set<String>()
        let t = now
        let r = MeshRouter(send: { _, p in sent.insert(p.id) }, deliver: { _ in }, maxStored: 8)
        r.receive(from: "good", Packet(id: "00000000000000a1", ts: t, ttl: 16, cipher: Data([1])))
        for i in 0..<50 { r.publish(Packet(id: String(format: "%016x", 1000 + i), ts: t, ttl: 16, cipher: Data([1])), from: "board") }
        sent = []; r.peerUp("new")
        XCTAssertTrue(sent.contains("00000000000000a1"), "the link's packet is still here")
        XCTAssertEqual(sent.count, 8, "with the newest of the others")
        // This phone's own packets count against no share, as before.
        let own = MeshRouter(send: { _, p in sent.insert(p.id) }, deliver: { _ in }, maxStored: 8)
        own.receive(from: "good", Packet(id: "00000000000000a2", ts: t, ttl: 16, cipher: Data([1])))
        for i in 0..<50 { own.publish(Packet(id: String(format: "%016x", 2000 + i), ts: t, ttl: 16, cipher: Data([1]))) }
        sent = []; own.peerUp("new")
        XCTAssertFalse(sent.contains("00000000000000a2"))
    }
}
