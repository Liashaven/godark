import XCTest
@testable import BlackoutCore

/// What a nearby device can make a phone's local links do (audit of 2026-11): the router's limits count per sender and
/// not per connection, a slow link gets the store in pieces, and link places can't be taken by one device.
/// Same scenarios as the Android LinkLimitsFixTest (router, queue and rule parts).
final class LinkLimitsFixTests: XCTestCase {
    private func now() -> Int64 { Int64(Date().timeIntervalSince1970 * 1000) }
    private func id(_ i: Int) -> String { String(format: "%016x", i) }
    private func pkt(_ i: Int, _ t: Int64, _ n: Int = 1, ttl: Int = 16) -> Packet { Packet(id: id(i), ts: t, ttl: ttl, cipher: Data(count: n)) }

    // MARK: - The router: one allowance per sender, however many links it opens

    // Four links from one address, two packets each, emptied an 8-packet store of everything the phone carried.
    func testLinksOfOneSenderShareOneShareOfTheStore() {
        var sent = Set<String>()
        let t = now(), r = MeshRouter(send: { _, p in sent.insert(p.id) }, deliver: { _ in }, maxStored: 8)
        r.receive(from: "good", pkt(0xa1, t))
        for l in 1...4 {
            r.peerUp("wifi:fake\(l)#\(l)", sender: "wifi:@10.0.0.9")
            for i in 0..<2 { r.receive(from: "wifi:fake\(l)#\(l)", pkt(1000 + l * 10 + i, t)) }
        }
        for l in 5...30 { // ... and the same device coming back under new link ids
            r.peerDown("wifi:fake\(l - 4)#\(l - 4)"); r.peerUp("wifi:fake\(l)#\(l)", sender: "wifi:@10.0.0.9")
            for i in 0..<2 { r.receive(from: "wifi:fake\(l)#\(l)", pkt(1000 + l * 10 + i, t)) }
        }
        sent = []; r.peerUp("new")
        XCTAssertTrue(sent.contains(id(0xa1)), "the first link's packet is still here")
        XCTAssertEqual(sent.count, 8)
    }

    // Without an address to go by (Bluetooth addresses are free to change), links are told apart only by their ids.
    // What they bring, all together, still can't push out what this phone wrote.
    func testAnyNumberOfLinksCantPushOutThisPhonesOwnPackets() {
        var sent = Set<String>()
        let t = now(), r = MeshRouter(send: { _, p in sent.insert(p.id) }, deliver: { _ in }, maxStored: 8)
        r.publish(pkt(0xa1, t)); r.publish(pkt(0xa2, t))
        for l in 1...40 { for i in 0..<2 { r.receive(from: "ble:\(l)", pkt(1000 + l * 10 + i, t)) } }
        sent = []; r.peerUp("new")
        XCTAssertTrue(sent.contains(id(0xa1)) && sent.contains(id(0xa2)), "this phone's own packets are still here")
        XCTAssertEqual(sent.count, 8, "and the newest of what the links brought")
        XCTAssertTrue(sent.contains(id(1000 + 40 * 10 + 1)))
    }

    // The phone's own packets keep at most half against the others: a phone that writes a lot still passes on.
    func testAPhoneThatWritesALotStillCarriesForItsNeighbours() {
        var sent = Set<String>()
        let t = now(), r = MeshRouter(send: { _, p in sent.insert(p.id) }, deliver: { _ in }, maxStored: 8)
        for i in 1...20 { r.publish(pkt(i, t)) }
        for l in 1...4 { r.receive(from: "ble:\(l)", pkt(100 + l, t)) } // four neighbours, one packet each
        sent = []; r.peerUp("new")
        XCTAssertTrue((1...4).allSatisfy { sent.contains(id(100 + $0)) })
        XCTAssertEqual(sent.filter { $0 < id(100) }, Set([17, 18, 19, 20].map(id)))
    }

    func testClosingALinkDoesNotStartANewMinute() {
        var t: Int64 = 1_000_000, got: [String] = []
        let r = MeshRouter(send: { _, _ in }, deliver: { got.append($0.id) }, now: { t }, maxPerMinute: 3)
        r.peerUp("a"); for i in 1...3 { r.receive(from: "a", pkt(i, t)) }
        r.peerDown("a"); r.peerUp("a"); for i in 4...6 { r.receive(from: "a", pkt(i, t)) }
        XCTAssertEqual(got.count, 3, "the link came back within its minute")
        // two links at once from one address, and a third after both closed: one allowance
        r.peerUp("wifi:x#1", sender: "wifi:@10.0.0.9"); r.peerUp("wifi:y#2", sender: "wifi:@10.0.0.9")
        r.receive(from: "wifi:x#1", pkt(11, t)); r.receive(from: "wifi:y#2", pkt(12, t))
        r.receive(from: "wifi:x#1", pkt(13, t)); r.receive(from: "wifi:y#2", pkt(14, t))
        r.peerDown("wifi:x#1"); r.peerDown("wifi:y#2"); r.peerUp("wifi:z#3", sender: "wifi:@10.0.0.9"); r.receive(from: "wifi:z#3", pkt(15, t))
        XCTAssertEqual(got.count, 6)
        r.peerUp("wifi:w#4", sender: "wifi:@10.0.0.7"); r.receive(from: "wifi:w#4", pkt(16, t))
        XCTAssertEqual(got.count, 7, "another address isn't held up")
        t += 60_000; r.receive(from: "a", pkt(6, t)); r.receive(from: "wifi:z#3", pkt(15, t))
        XCTAssertEqual(got.count, 9, "a minute later both go on")
    }

    // MARK: - The router: packets from before a restart aren't this phone's own

    func testRestoredPacketsGiveWayLikeOneSendersPackets() {
        var sent = Set<String>()
        let t = now(), r = MeshRouter(send: { _, p in sent.insert(p.id) }, deliver: { _ in }, maxStored: 8)
        r.restore((1...8).map { pkt(500 + $0, t + 60_000) }) // saved before the restart, dated ahead
        for i in 1...4 { r.receive(from: "good", pkt(0xa0 + i, t)) }
        sent = []; r.peerUp("new")
        XCTAssertTrue((1...4).allSatisfy { sent.contains(id(0xa0 + $0)) }, "all the link brought is kept")
        XCTAssertEqual(sent.filter { $0 > id(0xff) }, Set((5...8).map { id(500 + $0) }), "with the newest from before the restart")
        // ...and they don't count as written here: what links bring pushes them out before this phone's own packets
        let own = MeshRouter(send: { _, p in sent.insert(p.id) }, deliver: { _ in }, maxStored: 8)
        own.restore((1...6).map { pkt(500 + $0, t) }); own.publish(pkt(0xb1, t))
        for l in 1...20 { own.receive(from: "ble:\(l)", pkt(2000 + l, t)) }
        sent = []; own.peerUp("new")
        XCTAssertTrue(sent.contains(id(0xb1)))
        XCTAssertTrue(sent.isDisjoint(with: (1...6).map { id(500 + $0) }))
    }

    // MARK: - A slow link takes the store in pieces

    /// A Bluetooth link's send queue, drained the way BleLink does: one chunk at a time, reporting the room that opens.
    private final class SlowLink {
        let name = "ble:1"
        var out = BleProtocol.Outbox(), reader = BleProtocol.Reader(), got: [Packet] = [], worst = 0
        var router: MeshRouter!
        func send(_ p: Packet) { out.add(BleProtocol.frame(BleProtocol.packetType, p.encode())); worst = max(worst, out.bytes); freed() }
        private func freed() { let f = out.freed(); if f.packets > 0 { router.room(name, bytes: f.bytes, packets: f.packets) } }
        /// Sends up to `chunks` chunks; false when the queue is empty.
        @discardableResult func pump(_ chunks: Int = .max) -> Bool {
            var n = 0
            while n < chunks, let c = out.peek(509) {
                out.commit(); n += 1
                for f in try! reader.feed(c) { got.append(Packet.decode(f.payload)!) }
                freed()
            }
            return !out.isEmpty
        }
    }
    private func slow() -> (MeshRouter, SlowLink) {
        let l = SlowLink()
        let r = MeshRouter(send: { [unowned l] peer, p in if peer == l.name { l.send(p) } }, deliver: { _ in })
        l.router = r
        return (r, l)
    }

    // Sixty-six large packets, stored last, were all a Bluetooth neighbour ever got: the queue dropped the rest.
    func testASlowLinkGetsTheWholeStoreOldestFirst() {
        let t = now(), (r, l) = slow()
        for i in 1...434 { r.publish(pkt(i, t, 182)) }                     // the messages this phone carries
        for i in 1...66 { r.receive(from: "junk", pkt(10_000 + i, t, 16_000)) } // a neighbour's large packets, stored last
        r.peerUp(l.name, roomBytes: BleProtocol.roomBytes, roomPackets: BleProtocol.roomPackets)
        while l.pump(50) { }
        XCTAssertEqual(l.got.map(\.id), (1...434).map(id) + (1...66).map { id(10_000 + $0) })
        XCTAssertLessThanOrEqual(l.worst, BleProtocol.maxQueueBytes, "the queue never went over its limit, so nothing was dropped")
        XCTAssertEqual(l.got.first?.ttl, 15)
    }

    func testASlowLinkGetsNewPacketsInTurnAndNothingTwice() {
        let t = now(), (r, l) = slow()
        for i in 1...200 { r.receive(from: "wifi:a#1", pkt(i, t, 16_000)) } // more than the queue holds
        r.receive(from: l.name, pkt(900, t))                               // what the link brought itself doesn't go back
        r.peerUp(l.name, roomBytes: BleProtocol.roomBytes, roomPackets: BleProtocol.roomPackets)
        l.pump(40)
        r.publish(pkt(901, t)); r.receive(from: "wifi:a#1", pkt(902, t))   // new while the link is still behind
        XCTAssertFalse(l.got.contains { $0.id == id(901) })
        while l.pump(50) { }
        XCTAssertEqual(l.got.map(\.id), (1...200).map(id) + [id(901), id(902)])
        // caught up: a new packet goes at once
        r.publish(pkt(903, t)); l.pump()
        XCTAssertEqual(l.got.last?.id, id(903))
        // a copy with more hops of a packet it has goes again
        let n = l.got.count
        r.receive(from: "wifi:b#2", pkt(904, t, ttl: 3)); l.pump()
        r.receive(from: "wifi:c#3", pkt(904, t, ttl: 9)); l.pump()
        XCTAssertEqual(l.got.dropFirst(n).map(\.ttl), [2, 8])
        // a repeated HELLO (BleLink): everything stored goes again, in pieces as before
        let before = l.got.count
        r.peerUp(l.name); while l.pump(50) { }
        XCTAssertEqual(l.got.count - before, 204, "all but the one it brought itself")
        XCTAssertLessThanOrEqual(l.worst, BleProtocol.maxQueueBytes)
        // when the link closes, the router forgets its place
        r.peerDown(l.name); r.publish(pkt(905, t)); r.room(l.name, bytes: 1 << 20, packets: 100)
        XCTAssertFalse(l.pump())
    }

    func testTheQueueReportsTheRoomThatOpens() {
        var q = BleProtocol.Outbox(maxBytes: 100, maxFrames: 10)
        q.add(BleProtocol.hello(nodeId: "node"), hello: true)
        q.add(BleProtocol.frame(BleProtocol.packetType, Data(count: 30))); q.add(BleProtocol.frame(BleProtocol.packetType, Data(count: 40)))
        XCTAssertTrue(q.freed() == (0, 0))
        while q.count > 2 { _ = q.peek(20); q.commit() }                   // the HELLO went out: no packet room
        XCTAssertTrue(q.freed() == (0, 0))
        while q.count > 1 { _ = q.peek(20); q.commit() }
        XCTAssertTrue(q.freed() == (30, 1)); XCTAssertTrue(q.freed() == (0, 0))
        q.add(BleProtocol.frame(BleProtocol.packetType, Data(count: 60)))  // over the cap: the oldest unsent packet is dropped
        XCTAssertTrue(q.freed() == (40, 1))
        q.clear(); XCTAssertTrue(q.freed() == (0, 0))
        XCTAssertLessThanOrEqual(BleProtocol.roomBytes + 3 * BleProtocol.roomPackets + 1024, BleProtocol.maxQueueBytes)
        XCTAssertTrue(BleProtocol.roomPackets < BleProtocol.maxQueueFrames && BleProtocol.roomPackets >= 500)
    }

    // MARK: - Bluetooth: whoever says a phone's node id first doesn't keep that phone out

    func testALaterLinkTheOtherSideDialedStaysBesideTheFirst() {
        func twin(_ me: String, _ them: String, _ newCentral: Bool, _ oldCentral: Bool, _ apart: Int64, same: Bool = false) -> BleProtocol.Twin {
            BleProtocol.twin(myId: me, remoteId: them, newCentral: newCentral, oldCentral: oldCentral, apartMs: apart, sameDevice: same)
        }
        // Someone linked first under the real phone's id. When the real phone dials, its link stays: whatever the two
        // ids, and whether the first link was dialed by this phone or by the other side. (It used to be closed.)
        for (me, them) in [("aaaa", "bbbb"), ("bbbb", "aaaa")] { for oldCentral in [true, false] { for apart: Int64 in [10_000, 3_600_000] {
            XCTAssertEqual(twin(me, them, false, oldCentral, apart), .bothStay)
        } } }
        XCTAssertEqual(twin("aaaa", "bbbb", false, false, 0), .bothStay) // two that dialed in at the same moment: neither is closed for the other
        // Over the same radio connection it is the same device: the phone is linked already, as before.
        XCTAssertEqual(twin("aaaa", "bbbb", false, true, 20_000, same: true), .closeNew)
        // A link this phone dialed to a phone it is linked to already is closed, as before...
        XCTAssertEqual(twin("aaaa", "bbbb", true, false, 10_000), .closeNew); XCTAssertEqual(twin("bbbb", "aaaa", true, true, 10_000), .closeNew)
        XCTAssertEqual(twin("aaaa", "bbbb", true, true, 500), .closeOld)
        // ...and two phones that dialed each other at the same moment keep the link the smaller id dialed, as before.
        XCTAssertEqual(twin("aaaa", "bbbb", true, false, 500), .closeOld); XCTAssertEqual(twin("aaaa", "bbbb", false, true, 500), .closeNew)
        XCTAssertEqual(twin("bbbb", "aaaa", true, false, 500), .closeNew); XCTAssertEqual(twin("bbbb", "aaaa", false, true, 500), .closeOld)
        // The honest case, the other phone dials 20 s later: here both stay, there the phone closes the one it dialed.
        XCTAssertEqual(twin("aaaa", "bbbb", false, true, 20_000), .bothStay); XCTAssertEqual(twin("bbbb", "aaaa", true, false, 20_000), .closeNew)
    }

    // MARK: - Who gets a place, and which addresses are local

    func testOneAddressCantTakeEveryPlace() {
        func g(_ held: [String], _ a: String) -> LinkLimits.Place { LinkLimits.giveWay(held, address: a, max: 4, perAddress: 2) }
        XCTAssertEqual(g([], "x"), .room); XCTAssertEqual(g(["x", "y"], "x"), .room)
        XCTAssertEqual(g(["y", "x", "x"], "x"), .giveWay(1), "its own oldest makes room")
        XCTAssertEqual(g(["a", "x", "b", "x"], "c"), .giveWay(1), "the address with the most gives up its oldest")
        XCTAssertEqual(g(["a", "x", "a", "x"], "c"), .giveWay(0))
        XCTAssertEqual(g(["a", "b", "c", "d"], "e"), .full, "nobody holds more than one: the caller decides")
        // 40 connections from one address that say nothing leave room for everyone else
        var held: [String] = []
        for _ in 0..<40 {
            if case .giveWay(let i) = LinkLimits.giveWay(held, address: "10.0.0.9", max: LinkLimits.waiting, perAddress: LinkLimits.waitingPerAddress) { held.remove(at: i) }
            held.append("10.0.0.9")
        }
        XCTAssertEqual(held.count, LinkLimits.waitingPerAddress)
        XCTAssertEqual(LinkLimits.giveWay(held, address: "10.0.0.7", max: LinkLimits.waiting, perAddress: LinkLimits.waitingPerAddress), .room)
    }

    func testOnlyLocalAddressesCountAsTheLocalNetwork() {
        func v6(_ groups: [UInt16]) -> [UInt8] { groups.flatMap { [UInt8($0 >> 8), UInt8($0 & 0xff)] } }
        let mapped = { (a: [UInt8]) -> [UInt8] in [UInt8](repeating: 0, count: 10) + [0xff, 0xff] + a }
        for a: [UInt8] in [[10, 1, 2, 3], [172, 16, 0, 1], [172, 31, 255, 254], [192, 168, 43, 1], [169, 254, 7, 7],
                           v6([0xfe80, 0, 0, 0, 0, 0, 0, 1]), v6([0xfd12, 0x3456, 0, 0, 0, 0, 0, 1]), mapped([192, 168, 1, 5])] {
            XCTAssertTrue(LinkLimits.local(a), "\(a)")
        }
        for a: [UInt8] in [[8, 8, 8, 8], [172, 32, 0, 1], [192, 169, 1, 1], [100, 64, 0, 1], [127, 0, 0, 1], [0, 0, 0, 0],
                           v6([0, 0, 0, 0, 0, 0, 0, 1]), v6([0, 0, 0, 0, 0, 0, 0, 0]), v6([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888]), mapped([8, 8, 8, 8])] {
            XCTAssertFalse(LinkLimits.local(a), "\(a)")
        }
        // a network with public addresses: the same network as this phone's end of the connection
        XCTAssertTrue(LinkLimits.local(v6([0x2001, 0xdb8, 1, 2, 0, 0, 0, 0x99]), mine: v6([0x2001, 0xdb8, 1, 2, 0, 0, 0, 5])))
        XCTAssertFalse(LinkLimits.local(v6([0x2001, 0xdb8, 1, 3, 0, 0, 0, 0x99]), mine: v6([0x2001, 0xdb8, 1, 2, 0, 0, 0, 5])))
        XCTAssertTrue(LinkLimits.local([44, 1, 2, 3], mine: [44, 1, 2, 200])); XCTAssertFalse(LinkLimits.local([44, 1, 3, 3], mine: [44, 1, 2, 200]))
        XCTAssertFalse(LinkLimits.local([127, 0, 0, 1], mine: [127, 0, 0, 1]))
        XCTAssertFalse(LinkLimits.local([1, 2, 3, 4, 5]))
    }
}
