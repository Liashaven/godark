import XCTest
@testable import BlackoutCore

/// Whoever hands a phone the first copy of a packet must not decide what happens to the real one: found in the
/// 2026-11-13 audit. Each of these failed before its fix; Android's FirstCopyTest checks the same. Dummy keys only.
final class FirstCopyTests: XCTestCase {
    private let now: Int64 = 1_800_000_000_000
    private let anna = "1111111111111111", ben = "2222222222222222"
    private func pid(_ i: Int) -> String { String(format: "%016llx", i) }
    private func pkt(_ id: String, _ ttl: Int, _ fill: UInt8 = 0x55) -> Packet { Packet(id: id, ts: now, ttl: ttl, cipher: Data(repeating: fill, count: 98)) }

    /// A router with the limits Engine gives it. `sent`: "peer ttl" of everything passed on.
    private final class Rig {
        var got: [Packet] = [], sent: [String] = [], raised: [Int] = []
        private(set) var r: MeshRouter!
        init(_ now: Int64, perMinute: Int = MeshRouter.linkPerMinute) {
            r = MeshRouter(send: { [unowned self] peer, p in sent.append("\(peer) \(p.ttl)") }, deliver: { [unowned self] in got.append($0) }, now: { now },
                           minCipher: MeshRouter.minSealed, maxPerMinute: perMinute, unlimited: { $0 == "nostr" }, raised: { [unowned self] in raised.append($0.ttl) })
        }
    }

    // MARK: The header time is part of what a packet is: a copy with another time can't be opened

    func testTheKeyCoversTheIdTheHeaderTimeAndTheContentButNotTheTtl() {
        let p = pkt("00000000000000a1", 16)
        XCTAssertEqual(MeshRouter.key(p), "00000000000000a1:4d9c1a2194a8e806") // SHA-256 of ts (8 bytes, big-endian), then cipher
        XCTAssertEqual(MeshRouter.key(p.withTtl(3)), MeshRouter.key(p))
        XCTAssertEqual(MeshRouter.key(Packet(id: p.id, ts: p.ts - 1, ttl: 16, cipher: p.cipher)), "00000000000000a1:85b5782718fe85c3")
        XCTAssertNotEqual(MeshRouter.key(pkt(p.id, 16, 0x56)), MeshRouter.key(p))
        XCTAssertNotEqual(MeshRouter.key(pkt("00000000000000a2", 16)), MeshRouter.key(p))
    }

    func testACopyOfAGroupMessageWithAnotherHeaderTimeDoesNotStopTheRealOne() throws {
        let secret = Data(repeating: 9, count: 32)
        let writer = Keyring.Epoch.fresh(number: 6, made: now - 3_600_000, secret: secret, members: [anna, ben], admins: [anna])
        let reader = Keyring.Epoch.fresh(number: 6, made: now - 3_600_000, secret: secret, members: [anna, ben], admins: [anna])
        let id = String(format: "%04x", writer.group.mailbox) + "000000000001", t = now - 5_000
        let cipher = try writer.group.seal(messageKey: try XCTUnwrap(writer.messageKeys?.key(1, 0)), index: 1, counter: 0, id: id, ts: t, sender: ben, name: "Ben", text: "dummy text") { try MemberKey.sign(TestKeys.key, $0) }
        let real = Packet(id: id, ts: writer.group.hideTime(t, cipher), ttl: 16, cipher: cipher), copy = Packet(id: id, ts: real.ts - 1, ttl: 16, cipher: cipher)
        func text(_ p: Packet) -> String? { reader.open(p)?.message.text }
        XCTAssertNil(text(copy), "the copy can't be opened")

        let x = Rig(now); x.r.peerUp("ble:next")
        x.r.receive(from: "ble:attacker", copy); x.r.receive(from: "ble:honest", real); x.r.receive(from: "nostr", real)
        XCTAssertEqual(x.got.map(\.ts), [copy.ts, real.ts], "the copy, then the real packet once")
        XCTAssertEqual(x.got.map(text), [nil, "dummy text"])
        XCTAssertEqual(x.sent, ["ble:next 15", "ble:next 15"], "both are passed on")
    }

    func testACopyOfAChannelPacketWithAnotherHeaderTimeDoesNotStopTheRealOne() throws {
        // The sealing of receipts, introductions, new keys and Public messages. The copy comes from the relays first.
        let g = GroupCrypto.fromSecret(Data(repeating: 7, count: 32))
        let id = String(format: "%04x", g.mailbox) + "000000000002", t = now - 5_000
        let cipher = try g.seal(id: id, ts: t, sender: ben, name: "Ben", text: "dummy text 2")
        let real = Packet(id: id, ts: g.hideTime(t, cipher), ttl: 16, cipher: cipher), copy = Packet(id: id, ts: real.ts - 1, ttl: 16, cipher: cipher)
        XCTAssertNil(g.open(copy))
        let x = Rig(now)
        x.r.receive(from: "nostr", copy); x.r.receive(from: "ble:honest", real)
        XCTAssertEqual(x.got.map { g.open($0)?.text }, [nil, "dummy text 2"])
    }

    func testAfterARestartTheStoredCopyDoesNotStopTheRealPacket() throws {
        let g = GroupCrypto.fromSecret(Data(repeating: 7, count: 32))
        let id = String(format: "%04x", g.mailbox) + "000000000003", t = now - 5_000
        let cipher = try g.seal(id: id, ts: t, sender: ben, name: "Ben", text: "dummy text 3")
        let real = Packet(id: id, ts: g.hideTime(t, cipher), ttl: 16, cipher: cipher), copy = Packet(id: id, ts: real.ts - 1, ttl: 16, cipher: cipher)
        let x = Rig(now)
        x.r.restore([copy], seenIds: [MeshRouter.key(copy)]) // what Engine.startUp gives the router
        x.r.receive(from: "ble:honest", real)
        XCTAssertEqual(x.got.map { g.open($0)?.text }, ["dummy text 3"])
        x.r.receive(from: "ble:honest", copy)
        XCTAssertEqual(x.got.count, 1, "the stored copy is not shown again")
    }

    // MARK: The ttl isn't authenticated: the copy with the most hops left decides, not the first

    /// What the linked peer, the relays and a peer that links later get when only the real copy arrives.
    private let passedOn = ["ble:b 15", "nostr 15", "ble:c 15"]

    func testACopyThatCameFirstWithTtl1DoesNotStopThePacketFromBeingPassedOn() {
        let x = Rig(now); x.r.peerUp("ble:b"); x.r.peerUp("nostr")
        x.r.receive(from: "ble:x", pkt(pid(1), 1)); XCTAssertEqual(x.sent, [])
        x.r.receive(from: "ble:y", pkt(pid(1), 16)); x.r.peerUp("ble:c")
        XCTAssertEqual(x.sent, passedOn)
        XCTAssertEqual(x.got.map(\.ttl), [1], "shown once")
        XCTAssertEqual(x.raised, [16], "the engine is told to save the higher ttl")
    }

    func testACopyThatCameFirstFromTheRelaysWithTtl0DoesNotStopThePacketFromBeingPassedOn() {
        let x = Rig(now); x.r.peerUp("ble:b")
        x.r.receive(from: "nostr", pkt(pid(2), 0)); x.r.receive(from: "ble:y", pkt(pid(2), 16)); x.r.peerUp("ble:c")
        XCTAssertEqual(x.sent, ["ble:b 15", "ble:c 15"]); XCTAssertEqual(x.got.count, 1)
    }

    func testAfterARestartAStoredTtl1CopyIsStillRaised() {
        let x = Rig(now), stored = pkt(pid(3), 1)
        x.r.restore([stored], seenIds: [MeshRouter.key(stored)]); x.r.peerUp("ble:d")
        x.r.receive(from: "ble:y", pkt(pid(3), 16))
        XCTAssertEqual(x.sent, ["ble:d 15"]); XCTAssertTrue(x.got.isEmpty, "not shown again"); XCTAssertEqual(x.raised, [16])
    }

    func testACopyWithTheSameOrFewerHopsIsStillIgnored() {
        let x = Rig(now); x.r.peerUp("ble:b")
        x.r.receive(from: "ble:x", pkt(pid(4), 9)); x.r.receive(from: "ble:y", pkt(pid(4), 9)); x.r.receive(from: "ble:y", pkt(pid(4), 3)); x.r.receive(from: "ble:b", pkt(pid(4), 8))
        XCTAssertEqual(x.sent, ["ble:b 8"]); XCTAssertEqual(x.raised, []); XCTAssertEqual(x.got.count, 1)
        x.r.receive(from: "ble:y", pkt(pid(4), 64)) // above 16 counts as 16
        x.r.receive(from: "ble:x", pkt(pid(4), 40)) // and 16 again is not higher
        XCTAssertEqual(x.sent, ["ble:b 8", "ble:b 15"]); XCTAssertEqual(x.raised, [16])
    }

    func testPassingOnAgainCountsInTheLinksPace() {
        let x = Rig(now, perMinute: 3); x.r.peerUp("ble:b")
        for ttl in 2...6 { x.r.receive(from: "ble:x", pkt(pid(5), ttl)) } // one new packet and two raises, then the link is over its share
        XCTAssertEqual(x.sent, ["ble:b 1", "ble:b 2", "ble:b 3"])
        x.r.receive(from: "ble:y", pkt(pid(5), 6))                        // another link isn't held up
        x.r.receive(from: "nostr", pkt(pid(5), 7))                        // nor are the relays, which have their own limit
        XCTAssertEqual(x.sent, ["ble:b 1", "ble:b 2", "ble:b 3", "ble:b 5", "ble:b 6"])
    }

    func testALowTtlCopyGivenToACarrierDoesNotCutOffThePhonesBehindIt() {
        let n = CoreTests.Net(); ["a", "b", "c", "d"].forEach(n.add); n.link("a", "b"); n.link("b", "c"); n.link("c", "d")
        let real = Packet(id: pid(6), ts: Int64(Date().timeIntervalSince1970 * 1000), ttl: 16, cipher: Data([1]))
        n.nodes["b"]!.receive(from: "attacker", real.withTtl(1)) // b reads it, but would never pass it on
        n.nodes["a"]!.publish(real); n.pump()
        for node in ["b", "c", "d"] { XCTAssertEqual(n.got[node], [real.id], node) }
    }

    // MARK: The LoRa queue tells packets apart as the router does

    func testJunkUnderAnIdDoesNotKeepTheRealPacketOffTheRadio() {
        var t = now
        let q = LoraQueue(now: { t })
        q.offer(pkt(pid(7), 16, 7))  // junk under the id
        q.offer(pkt(pid(7), 16, 9))  // the real packet
        q.offer(pkt(pid(7), 15, 9))  // the real packet again, one hop later: not sent twice
        XCTAssertEqual(q.next()?.cipher.first, 7); t += LoraQueue.intervalMs
        XCTAssertEqual(q.next()?.cipher.first, 9); t += LoraQueue.intervalMs
        XCTAssertNil(q.next())
    }

    /// The router hands packets for the radio peer to a queue, as Engine.route and LoraLink.offer do.
    private func overTheRadio(_ maxBytes: Int, _ radio: String, _ arrivals: [(String, Packet)]) -> [UInt8?] {
        var t = now
        let q = LoraQueue(maxBytes: maxBytes, now: { t })
        let r = MeshRouter(send: { peer, p in if peer == radio { q.offer(p) } }, deliver: { _ in }, now: { t },
                           minCipher: MeshRouter.minSealed, maxPerMinute: MeshRouter.linkPerMinute, unlimited: { $0 == "nostr" })
        r.peerUp(radio)
        for (link, p) in arrivals { r.receive(from: link, p) }
        return (1...3).map { _ in defer { t += LoraQueue.intervalMs }; return q.next()?.cipher.first }
    }

    func testJunkSentFirstUnderAnIdIsFollowedByTheRealPacketOnBothRadios() {
        let junk = Packet(id: "a8d00000000000c1", ts: now, ttl: 16, cipher: Data(repeating: 7, count: 100))
        let real = Packet(id: junk.id, ts: now - 5 * 60_000, ttl: 16, cipher: Data(repeating: 9, count: 100))
        let arrivals = [("nearby:attacker", junk), ("nearby:honest", real)]
        XCTAssertEqual(overTheRadio(Meshtastic.payloadMax, "lora", arrivals), [7, 9, nil])
        XCTAssertEqual(overTheRadio(MeshCore.payloadMax, "meshcore", arrivals), [7, 9, nil])
        XCTAssertEqual(overTheRadio(Meshtastic.payloadMax, "lora", arrivals.reversed()), [9, 7, nil])
    }

    func testAPacketPassedOnAgainWithMoreHopsGoesOverTheRadioOnce() {
        let p = pkt(pid(8), 5)
        XCTAssertEqual(overTheRadio(Meshtastic.payloadMax, "lora", [("ble:x", p), ("ble:y", p.withTtl(16))]), [0x55, nil, nil])
    }
}
