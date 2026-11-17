import XCTest
@testable import BlackoutCore

/// The relay outbox, the catch-up, the LoRa queue, the Everyone store and the Everyone introduction (audit of 2026-11).
/// Each test of a rule in the outbox, the catch-up and the LoRa queue failed before its fix; Android's
/// RelayLimitsFixTest checks the same. Dummy packets and mailboxes only; no socket, no relay.
///
/// NostrLink, RelayScope and Engine are in the app, so the tests run the rules they are made of (`RelayOutbox`,
/// `CatchUp`, `RelaySince`, `MeshRouter.source`, `LoraQueue`, `StoreCap.everyone`, `PublicIntro`); `Phone` and `link`
/// wire them the way Engine.route and RelayScope's message handler do.
final class RelayLimitsFixTests: XCTestCase {
    private static let relays = "nostr", lora = "lora" // NostrLink.peer, LoraLink.peer
    private let t0: Int64 = 1_800_000_000_000
    private func pkt(_ id: String, _ fill: UInt8, ts: Int64? = nil, size: Int = MeshRouter.minSealed, ttl: Int = 15) -> Packet {
        Packet(id: id, ts: ts ?? t0 - 1_000, ttl: ttl, cipher: Data(repeating: fill, count: size))
    }
    private func id(_ prefix: String, _ n: Int) -> String { prefix + String(format: "%012x", n) }
    private func outbox(_ sent: [String] = []) -> RelayOutbox { let t = t0; return RelayOutbox(sent: sent, now: { t }, jitter: { 0 }) }

    /// The router's relay and radio peers, wired to an outbox and a LoRa queue the way Engine.route does it.
    private final class Phone {
        var mine = Set<String>()                              // ids of packets written on this phone
        let outbox: RelayOutbox
        let radio: LoraQueue
        var offered: [String] = []                            // what the relay peer was told: "mine from"
        var router: MeshRouter!

        init(now: @escaping () -> Int64) {
            outbox = RelayOutbox(now: now, jitter: { 0 })
            radio = LoraQueue(now: now)
            router = MeshRouter(send: { [unowned self] peer, p in
                let from = self.router.source(p), own = from == "" && self.mine.contains(p.id)
                if peer == RelayLimitsFixTests.relays { self.offered.append("\(own) \(from ?? "")"); self.outbox.offer(p, mine: own, from: from ?? "") }
                if peer == RelayLimitsFixTests.lora { self.radio.offer(p, mine: own) }
            }, deliver: { _ in }, now: now, minCipher: MeshRouter.minSealed)
        }
    }

    // MARK: - 1. The outbox tells packets apart by id, time and content, never by id alone

    // Any neighbour could send another packet under the id of one this phone wrote. It took the real one's place in
    // the queue, went up instead of it, and its acceptance made the real one count as sent, also after a restart.
    func testAnotherPacketUnderTheIdOfAnOwnOneNeitherTakesItsPlaceNorCountsAsIt() throws {
        let t = t0, phone = Phone(now: { t })
        phone.router.peerUp(Self.relays); phone.router.peerUp("ble:neighbour")
        let real = pkt("a8d00000000000e1", 1, ttl: 16)
        phone.mine.insert(real.id); phone.router.publish(real)
        for i in 0..<5 { phone.router.receive(from: "ble:neighbour", pkt(real.id, UInt8(10 + i), ts: t0 - 500)) }
        // Only the packet this phone wrote is its own; the others are a link's, whatever id they carry.
        XCTAssertEqual(phone.offered, ["true "] + Array(repeating: "false ble:neighbour", count: 5))
        let o = phone.outbox
        let (first, own) = try XCTUnwrap(o.next(bridged: false))
        XCTAssertEqual(first.cipher.first, 1); XCTAssertTrue(own)
        XCTAssertNil(o.next(bridged: false), "the others wait with the packets passed on")
        o.posted(eventId: "ev-real", first, fromOwn: own, relays: ["r"])
        // While the real one is in flight, the others are still looked up and posted like anyone's.
        let batch = o.toCheck(50); XCTAssertEqual(batch.count, 5)
        XCTAssertEqual(o.checked(batch), [])
        let (other, otherOwn) = try XCTUnwrap(o.next(bridged: true)); XCTAssertFalse(otherOwn)
        o.posted(eventId: "ev-other", other, fromOwn: otherOwn, relays: ["r"])
        XCTAssertNil(o.answer(relay: "r", Nostr.Ok(eventId: "ev-other", accepted: true, reason: "")), "a relay taking someone else's packet is no \"Sent\" for this phone's message")
        XCTAssertTrue(o.isSent(other)); XCTAssertFalse(o.isSent(real))
        XCTAssertEqual(o.answer(relay: "r", Nostr.Ok(eventId: "ev-real", accepted: true, reason: "")), real.id)
        XCTAssertTrue(o.isSent(real))
    }

    func testAPacketThatWentUpFirstUnderAnIdDoesNotStopTheRealOne() throws {
        let real = pkt("a8d00000000000e2", 1, ttl: 16), fake = pkt(real.id, 2, ts: t0 - 500)
        let o = outbox()
        o.offer(fake, mine: false, from: "ble:x")
        _ = o.checked(o.toCheck(50))
        let (p, own) = try XCTUnwrap(o.next(bridged: true)); o.posted(eventId: "ev1", p, fromOwn: own, relays: ["r"])
        o.offer(real, mine: true)                                            // was dropped: "its id is in flight"
        XCTAssertEqual(o.next(bridged: false)?.packet.cipher.first, 1)
        _ = o.answer(relay: "r", Nostr.Ok(eventId: "ev1", accepted: true, reason: ""))
        o.offer(real, mine: true)                                            // was dropped: "its id is sent"
        XCTAssertEqual(o.next(bridged: false)?.packet.cipher.first, 1)

        // The saved list names the very packet, so after a restart too only that one counts as sent.
        let saved = o.sentList(); XCTAssertEqual(saved, [MeshRouter.key(fake)])
        let restarted = outbox(saved)
        restarted.offer(fake, mine: false); XCTAssertEqual(restarted.queued, 0)
        restarted.offer(real, mine: true); XCTAssertEqual(restarted.queued, 1)
        // What an older build saved by id alone stands for no packet: the real one is looked up or posted again.
        let upgraded = outbox([real.id])
        upgraded.offer(real, mine: true); XCTAssertEqual(upgraded.queued, 1); XCTAssertFalse(upgraded.isSent(real.id))
    }

    func testTwoPacketsUnderOneIdBothWaitAndARelaysCopyOfOneSaysNothingAboutTheOther() {
        let real = pkt("beef00000000c001", 1), fake = pkt(real.id, 2)
        let o = outbox()
        o.offer(real, mine: false, from: "ble:a"); o.offer(fake, mine: false, from: "ble:b")
        XCTAssertEqual(o.queued, 2, "neither replaces the other")
        let batch = o.toCheck(50); XCTAssertEqual(batch.count, 2)
        _ = o.fromRelay(fake)                                                // the relays have the other packet only
        _ = o.checked(batch)
        var posted: [UInt8?] = []
        while let n = o.next(bridged: true) { posted.append(n.packet.cipher.first) }
        XCTAssertEqual(posted, [1])

        // A relay that sends the real packet and then another under its id: the real one still counts as there.
        let again = outbox()
        again.offer(real, mine: false)
        let asked = again.toCheck(50)
        _ = again.fromRelay(real.withTtl(3)); _ = again.fromRelay(fake)
        _ = again.checked(asked)
        XCTAssertNil(again.next(bridged: true), "not posted a second time"); XCTAssertTrue(again.isSent(real))
    }

    func testTheRouterSaysWhereThisVeryPacketCameFrom() {
        let t = t0
        let r = MeshRouter(send: { _, _ in }, deliver: { _ in }, now: { t }, minCipher: MeshRouter.minSealed)
        let own = pkt("a8d00000000000e3", 1, ttl: 16), other = pkt(own.id, 2), board = pkt("957600000000e004", 3, ttl: 16)
        XCTAssertNil(r.source(own))
        r.publish(own); r.receive(from: "wifi:n", other); r.publish(board, from: "board")
        XCTAssertEqual(r.source(own), ""); XCTAssertEqual(r.source(own.withTtl(3)), "")
        XCTAssertEqual(r.source(other), "wifi:n", "another packet under the id is the link's")
        XCTAssertEqual(r.source(board), "board")
        // After a restart: what the phone held is its own or unknown (""), unless the caller knows a relay brought it.
        let again = MeshRouter(send: { _, _ in }, deliver: { _ in }, now: { t }, minCipher: MeshRouter.minSealed)
        again.restore([own, board], from: { $0 == MeshRouter.key(board) ? Self.relays : "" })
        XCTAssertEqual(again.source(own), ""); XCTAssertEqual(again.source(board), Self.relays); XCTAssertNil(again.source(other))
    }

    // MARK: - 2. Catch-up: junk in a mailbox neither ends it early nor makes the phone skip what it didn't fetch

    private let box: UInt16 = 0xa8d0
    private let nowS: Int64 = 1_800_000_000
    private var real: Packet { Packet(id: "a8d0000000000001", ts: (nowS - 50_000) * 1000, ttl: 15, cipher: Data(repeating: 1, count: MeshRouter.minSealed)) }
    private typealias Stored = (at: Int64, content: String)

    private func frame(_ sub: String, _ created: Int64, _ content: String) -> String {
        let e: [String: Any] = ["id": String(repeating: "0", count: 64), "pubkey": String(repeating: "1", count: 64), "created_at": created,
                                "kind": Nostr.kind, "tags": [["t", Nostr.tag(box)]], "content": content, "sig": String(repeating: "2", count: 128)]
        return "[\"EVENT\",\"\(sub)\"," + String(decoding: try! JSONSerialization.data(withJSONObject: e), as: UTF8.self) + "]"
    }
    private func content(_ p: Packet) -> String { p.encode().base64EncodedString() }

    /// An honest relay with these stored events: it answers a REQ with the newest 500 of the window.
    private func answer(_ events: [Stored], _ r: CatchUp.Req) -> [String] {
        events.filter { $0.at >= r.since && (r.until == nil || $0.at <= r.until!) }.sorted { $0.at > $1.at }.prefix(Nostr.page)
            .map { frame(r.subId, $0.at, $0.content) }
    }

    /// One link to the relay: catches `mailbox` up as RelayScope does. Returns the REQs sent and the packets that arrived.
    private func link(_ events: [Stored], _ since: RelaySince, now: Int64, mailbox: UInt16? = nil) -> (reqs: [CatchUp.Req], got: [Packet]) {
        let cu = CatchUp(relay: "wss://r", since: since); cu.add([mailbox ?? box])
        var reqs: [CatchUp.Req] = [], got: [Packet] = []
        var req = cu.next(now: now)
        while let r = req {
            reqs.append(r)
            for text in answer(events, r) { cu.frame(text); if let e = Nostr.received(text) { got.append(e.packet) } }
            req = cu.end(r.subId, complete: true, now: now)
        }
        return (reqs, got)
    }

    func testReadsTheDateOfAnyEvent() throws {
        let d = try XCTUnwrap(Nostr.dated(frame("cu7", 123, "x")))
        XCTAssertEqual(d.subId, "cu7"); XCTAssertEqual(d.createdAt, 123)
        XCTAssertNil(Nostr.received(frame("cu7", 123, "x")))                 // no packet in it
        XCTAssertNil(Nostr.dated("[\"EOSE\",\"cu7\"]")); XCTAssertNil(Nostr.dated("[\"EVENT\",\"cu7\"]")); XCTAssertNil(Nostr.dated("nonsense"))
    }

    // 500 events with the mailbox's tag and content that is no packet used to count as an empty page: the catch-up
    // ended there, and the saved start moved past the real event below them.
    func testAPageOfEventsThatCarryNoPacketIsStillAFullPage() {
        let events: [Stored] = [(nowS - 50_000, content(real))] + (0..<Int64(Nostr.page)).map { (nowS - 40_000 + $0, "x") }
        let since = RelaySince(); since.advance("wss://r", box, to: nowS - 60_000)
        let (reqs, got) = link(events, since, now: nowS)
        XCTAssertEqual(reqs.count, 2); XCTAssertEqual(reqs.last?.until, nowS - 40_000)
        XCTAssertEqual(got.map(\.id), [real.id])
        XCTAssertEqual(since.get("wss://r", box), nowS); XCTAssertNil(since.owed("wss://r", box))
    }

    // 2,000 junk packets used up the four pages; the catch-up counted as done, and no later link asked for anything older.
    func testACatchUpThatStopsAtItsPageLimitOwesTheRestToTheNextLinks() throws {
        let junk: [Stored] = (0..<Int64(2_500)).map { i in
            (nowS - 40_000 + i, content(Packet(id: id("a8d0", 1000 + Int(i)), ts: (nowS - 40_000 + i) * 1000, ttl: 15, cipher: Data(repeating: 9, count: MeshRouter.minSealed))))
        }
        let events = junk + [(nowS - 50_000, content(real))]
        var since = RelaySince(); since.advance("wss://r", box, to: nowS - 60_000)
        let (first, got) = link(events, since, now: nowS)
        XCTAssertEqual(first.count, Nostr.maxPages); XCTAssertFalse(got.contains { $0.id == real.id })
        XCTAssertEqual(since.get("wss://r", box), nowS, "new events are asked from here, as before")
        let owed = try XCTUnwrap(since.owed("wss://r", box))
        XCTAssertEqual(owed.from, nowS - 60_000 - Nostr.sinceMarginSeconds)  // everything since the old start…
        XCTAssertEqual(owed.from, first.last?.since); XCTAssertLessThan(owed.until, try XCTUnwrap(first.last?.until)) // …that is older than the last page

        since = RelaySince(since.save())                                     // the app restarts in between
        XCTAssertEqual(since.owed("wss://r", box)?.from, owed.from); XCTAssertEqual(since.owed("wss://r", box)?.until, owed.until)
        let (second, more) = link(events, since, now: nowS + 600)
        XCTAssertLessThanOrEqual(second.count, Nostr.maxPages, "no more REQs than a link may send")
        XCTAssertNil(second[0].until); XCTAssertEqual(second[0].since, nowS - Nostr.sinceMarginSeconds) // first what is new
        XCTAssertEqual(second[1].since, owed.from); XCTAssertEqual(second[1].until, owed.until)         // then what was left out
        XCTAssertTrue(more.contains { $0.id == real.id }, "the real event is fetched")
        XCTAssertNil(since.owed("wss://r", box), "nothing is owed any more")
        XCTAssertEqual(since.get("wss://r", box), nowS + 600)
        XCTAssertEqual(link(events, since, now: nowS + 1_200).reqs.count, 1) // caught up: one REQ, as always
    }

    func testADeeperFloodIsReadFurtherOnEveryLink() throws {
        let junk: [Stored] = (0..<Int64(5_000)).map { (nowS - 40_000 + $0, "x") }
        let events = junk + [(nowS - 50_000, content(real))]
        let since = RelaySince(); since.advance("wss://r", box, to: nowS - 60_000)
        var links = 0, fetched = false, last = Int64.max
        while !fetched && links < 10 {
            let (reqs, got) = link(events, since, now: nowS + Int64(links) * 600); links += 1
            XCTAssertLessThanOrEqual(reqs.count, Nostr.maxPages)
            fetched = got.contains { $0.id == real.id }
            if !fetched { let until = try XCTUnwrap(since.owed("wss://r", box)).until; XCTAssertLessThan(until, last, "each link gets further"); last = until }
        }
        XCTAssertTrue(fetched); XCTAssertEqual(links, 4)                     // 4 pages, then 3 older ones on each later link: the 11th isn't full
        XCTAssertNil(since.owed("wss://r", box))
    }

    func testTheEveryoneChannelStaysOnePageAndWhatIsOwedIsNeverOlderThanSevenDays() {
        let everyone: [Stored] = (0..<Int64(600)).map { (nowS - 1_000 + $0, "x") }
        let since = RelaySince()
        XCTAssertEqual(link(everyone, since, now: nowS, mailbox: Nostr.publicMailbox).reqs.count, 1)
        XCTAssertEqual(since.get("wss://r", Nostr.publicMailbox), nowS)
        XCTAssertNil(since.owed("wss://r", Nostr.publicMailbox), "one page by design: nothing is owed")

        since.owe("wss://r", box, from: nowS - 9 * 86_400, until: nowS - 8 * 86_400) // left out over a week ago: relays no longer keep it
        XCTAssertEqual(link([], since, now: nowS).reqs.count, 1)
        XCTAssertNil(since.owed("wss://r", box))
        since.owe("wss://r", box, from: nowS - 8 * 86_400, until: nowS - 86_400)     // partly older: asked from 7 days back
        let part = link([], since, now: nowS).reqs
        XCTAssertEqual(part.count, 2); XCTAssertEqual(part.last?.since, nowS - Nostr.keepSeconds); XCTAssertEqual(part.last?.until, nowS - 86_400)
    }

    func testWhatIsOwedIsSavedWithTheStartsAndOlderSavedListsStillRead() {
        let s = RelaySince("wss://a|a8d0=100,wss://b|0794=7")                // as saved before this change
        XCTAssertEqual(s.get("wss://a", 0xa8d0), 100); XCTAssertNil(s.owed("wss://a", 0xa8d0)); XCTAssertFalse(s.changed)
        s.owe("wss://a", 0xa8d0, from: 40, until: 90); XCTAssertTrue(s.changed)
        XCTAssertEqual(s.save(), "wss://a|a8d0=100,wss://b|0794=7,wss://a|a8d0|from=40,wss://a|a8d0|until=90")
        let t = RelaySince(s.save())
        XCTAssertEqual(t.owed("wss://a", 0xa8d0)?.from, 40); XCTAssertEqual(t.owed("wss://a", 0xa8d0)?.until, 90)
        XCTAssertNil(t.owed("wss://b", 0x0794)); XCTAssertEqual(t.get("wss://a", 0xa8d0), 100)
        t.owe("wss://a", 0xa8d0, from: 40, until: 90); XCTAssertFalse(t.changed, "nothing moved")
        t.owe("wss://a", 0xa8d0, from: 40, until: 40); XCTAssertTrue(t.changed) // nothing left
        XCTAssertNil(t.owed("wss://a", 0xa8d0)); XCTAssertEqual(t.save(), "wss://a|a8d0=100,wss://b|0794=7")
    }

    // MARK: - 3. The queues for packets passed on are bounded in bytes

    // 5,000 + 2,000 packets of 16 KB: a neighbour could park over 100 MB in memory.
    func testTheQueuesForPacketsPassedOnAreBoundedInBytes() {
        let o = outbox(), big = Data(repeating: 7, count: Packet.maxCipher), one = Packet.headerSize + big.count
        var n = 0
        func flood(_ count: Int) {
            for _ in 0..<count { o.offer(Packet(id: id("beef", n), ts: t0 - 3_600_000 + Int64(n), ttl: 15, cipher: big), mine: false, from: "wifi:x"); n += 1 }
        }
        flood(3_000)
        XCTAssertEqual(o.queued, RelayOutbox.queueBytes / one, "as many as fit in the budget")
        XCTAssertLessThanOrEqual(o.queuedBytes, RelayOutbox.queueBytes)      // was 48 MB
        for _ in 0..<60 { _ = o.checked(o.toCheck(50)); flood(100) }         // looked up, not found: they wait to be posted
        XCTAssertLessThanOrEqual(o.queuedBytes, 2 * RelayOutbox.queueBytes)  // the two queues together
        XCTAssertGreaterThan(o.queuedBytes, RelayOutbox.queueBytes)          // and both are in use

        let small = outbox()                                                 // short packets: the counts are the limit, as before
        for i in 0..<RelayOutbox.candidatesMax + 100 { small.offer(pkt(id("beef", i), 9, ts: t0 - 60_000 + Int64(i)), mine: false) }
        XCTAssertEqual(small.queued, RelayOutbox.candidatesMax)
    }

    // MARK: - 5. This phone's older messages have their own way up, and the links that brought the rest take turns

    // A message written without internet is over 40 minutes old by the time the relays link. It waited behind every
    // packet with a later date, and the date is whatever the packet's maker wrote, up to 10 minutes ahead.
    func testANeighboursForwardDatedPacketsDoNotGoBeforeThisPhonesOlderMessage() throws {
        let o = outbox()
        let own = pkt("a8d00000000000f1", 1, ts: t0 - 41 * 60_000, ttl: 16)
        o.offer(own, mine: true)
        XCTAssertNil(o.next(bridged: false), "older than 40 minutes: looked up first")
        for i in 0..<60 { o.offer(pkt(id("beef", i), 9, ts: t0 + 9 * 60_000 + Int64(i)), mine: false, from: "ble:loud") }
        let batch = o.toCheck(50)
        XCTAssertEqual(batch.first?.id, own.id, "looked up before anything passed on")
        _ = o.checked(batch)
        let (p, mine) = try XCTUnwrap(o.next(bridged: false))                // and posted with the own packets, at their pace
        XCTAssertEqual(p.id, own.id); XCTAssertTrue(mine)
    }

    func testABurstOfForwardDatedPacketsDoesNotPushThisPhonesOlderMessageOut() {
        let o = outbox()
        let own = pkt("a8d00000000000f2", 1, ts: t0 - 41 * 60_000, ttl: 16)
        o.offer(own, mine: true)
        let c = Data(repeating: 9, count: MeshRouter.minSealed)
        for i in 0..<RelayOutbox.candidatesMax + RelayOutbox.missingMax + 50 {
            o.offer(Packet(id: id("beef", i), ts: t0 + 9 * 60_000 + Int64(i), ttl: 15, cipher: c), mine: false, from: "ble:loud")
        }
        XCTAssertEqual(o.queued, RelayOutbox.candidatesMax)
        XCTAssertEqual(o.toCheck(50).first?.id, own.id)
    }

    func testTheLinksThatBroughtPacketsTakeTurns() {
        let o = outbox()
        for i in 0..<200 { o.offer(pkt(id("beef", i), 9, ts: t0 + 9 * 60_000 + Int64(i)), mine: false, from: "ble:loud") }
        let quiet = (0..<3).map { pkt(id("cafe", $0), 5, ts: t0 - 30 * 60_000 - Int64($0)) }
        quiet.forEach { o.offer($0, mine: false, from: "wifi:quiet") }
        let batch = o.toCheck(50)
        XCTAssertTrue(Set(batch.map(\.id)).isSuperset(of: quiet.map(\.id)), "the quiet link's packets are looked up in the first batch")
        XCTAssertEqual(batch.count, 50)
        _ = o.checked(batch)
        XCTAssertEqual((1...7).map { _ in String(o.next(bridged: true)?.packet.id.prefix(4) ?? "") }, ["beef", "cafe", "beef", "cafe", "beef", "cafe", "beef"])
        // A packet from a link not seen before waits one turn, not for the whole queue of the loud one.
        o.offer(pkt("f00d00000000c001", 6, ts: t0 - 20 * 60_000), mine: false, from: "nearby:new")
        _ = o.checked(o.toCheck(50))
        XCTAssertTrue((1...2).map { _ in String(o.next(bridged: true)?.packet.id.prefix(4) ?? "") }.contains("f00d"))
    }

    func testAFullQueueTakesFromTheLinkThatHoldsMoreThanAQuarter() {
        let o = outbox()
        for i in 0..<100 { o.offer(pkt(id("cafe", i), 5, ts: t0 - 3_600_000 - Int64(i)), mine: false, from: "wifi:quiet") }
        let c = Data(repeating: 9, count: MeshRouter.minSealed)
        for i in 0..<RelayOutbox.candidatesMax + 500 {
            o.offer(Packet(id: id("beef", i), ts: t0 + 9 * 60_000 + Int64(i), ttl: 15, cipher: c), mine: false, from: "ble:loud")
        }
        XCTAssertEqual(o.queued, RelayOutbox.candidatesMax)
        var waiting: [String] = []
        while case let b = o.toCheck(50), !b.isEmpty { waiting += b.map(\.id) }
        XCTAssertEqual(waiting.filter { $0.hasPrefix("cafe") }.count, 100, "none of the quiet link's older packets was pushed out")
        XCTAssertEqual(waiting.filter { $0.hasPrefix("beef") }.count, RelayOutbox.candidatesMax - 100)
        XCTAssertFalse(waiting.contains(id("beef", 0)), "the loud link's own oldest made room")
    }

    // MARK: - 6. The LoRa queue sends this phone's own packets first

    // 20 packets passed on after it pushed the phone's own message out of the queue for good, and it showed "Sent".
    func testPacketsPassedOnDoNotPushThisPhonesOwnMessageOutOfTheRadioQueue() {
        var t = t0
        let q = LoraQueue(now: { t })
        q.offer(Packet(id: "00000000000000f0", ts: t, ttl: 16, cipher: Data(count: 10))); XCTAssertNotNil(q.next()) // the 20 s until the next one are running
        let own = Packet(id: "00000000000000a1", ts: t, ttl: 16, cipher: Data(count: 10))
        q.offer(own, mine: true)
        for i in 0..<3 * LoraQueue.maxQueue { q.offer(Packet(id: String(format: "00000000000001%02x", i), ts: t, ttl: 15, cipher: Data(count: 10))) }
        t += LoraQueue.intervalMs
        XCTAssertEqual(q.next()?.id, own.id, "the phone's own goes first")
        var after: [String] = []
        while true { t += LoraQueue.intervalMs; guard let p = q.next() else { break }; after.append(p.id) }
        XCTAssertEqual(after, (41..<60).map { String(format: "00000000000001%02x", $0) }, "then the newest that fit, in the order they came")
    }

    func testTheRadioQueueKeepsItsOwnPacketsWhenFull() {
        var t = t0
        let q = LoraQueue(now: { t })
        let own = (0..<LoraQueue.maxQueue + 2).map { Packet(id: String(format: "00000000000002%02x", $0), ts: t0, ttl: 16, cipher: Data(count: 10)) }
        own.prefix(LoraQueue.maxQueue).forEach { q.offer($0, mine: true) }
        q.offer(Packet(id: "00000000000000b1", ts: t, ttl: 15, cipher: Data(count: 10))) // full of own packets: one passed on isn't taken
        own.dropFirst(LoraQueue.maxQueue).forEach { q.offer($0, mine: true) }            // more own ones: the oldest own make room
        var aired: [String] = []
        while true { t += LoraQueue.intervalMs; guard let p = q.next() else { break }; aired.append(p.id) }
        XCTAssertEqual(aired, own.dropFirst(2).map(\.id))
    }

    func testTheRouterFeedsTheRadioQueueAndOnlyThePhonesOwnPacketGoesFirst() {
        let t = t0, phone = Phone(now: { t })
        phone.router.peerUp(Self.lora); phone.router.peerUp("ble:n")
        let own = pkt("00000000000000a2", 1, ts: t0, ttl: 16)
        for i in 0..<5 { phone.router.receive(from: "ble:n", pkt(String(format: "00000000000003%02x", i), 9, ts: t0)) }
        phone.router.receive(from: "ble:n", pkt(own.id, 8, ts: t0))          // another packet under the id it is about to use
        phone.mine.insert(own.id); phone.router.publish(own)
        for i in 5..<40 { phone.router.receive(from: "ble:n", pkt(String(format: "00000000000003%02x", i), 9, ts: t0)) }
        let first = phone.radio.next()
        XCTAssertEqual(first?.id, own.id); XCTAssertEqual(first?.cipher.first, 1)
    }

    // MARK: - 7. The Everyone store: one sender can't push everyone else out

    private func held(_ prefix: String, _ n: Int, from: Int64, own: Bool = false, holder: (Int) -> String) -> [StoreCap.Held] {
        (0..<n).map { StoreCap.Held(id: prefix + String(format: "%05d", $0), ts: from + Int64($0), holder: holder($0), own: own) }
    }

    // The newest 2,000 stayed, whoever sent them: 2,000 packets from one key emptied the channel and every place in it.
    func testOneSenderCantPushEveryoneElseOutOfTheEveryoneStore() {
        let honest = held("h", 300, from: 1_000) { "sender-\($0 % 60)" }     // 60 people, 5 packets each, all older
        let flood = held("f", 2_500, from: 10_000) { _ in "flooder" }
        let drop = StoreCap.everyone(honest + flood, max: 2_000)
        XCTAssertEqual(drop, (0..<800).map { "f" + String(format: "%05d", $0) }) // only the flooder's, its oldest first
        XCTAssertEqual(StoreCap.everyone(honest + flood.prefix(1_700), max: 2_000), []) // at the cap: nothing goes
        // The same for a flood of introductions, and for packets whose sender can't be checked: each counts as one holder.
        let intros = held("i", 3_000, from: 10_000) { _ in "introductions" }, unknown = held("u", 3_000, from: 20_000) { _ in "not verified" }
        let gone = Set(StoreCap.everyone(honest + intros + unknown, max: 2_000))
        XCTAssertEqual(gone.count, 4_300); XCTAssertFalse(gone.contains { $0.hasPrefix("h") })
        XCTAssertEqual(intros.filter { !gone.contains($0.id) }.count, 850); XCTAssertEqual(unknown.filter { !gone.contains($0.id) }.count, 850)
    }

    func testTheEveryoneStoreKeepsThisPhonesOwnAndOtherwiseTheNewest() {
        // No sender over a quarter: the oldest go, as before.
        let many = held("m", 2_100, from: 1_000) { "sender-\($0 % 700)" }
        XCTAssertEqual(StoreCap.everyone(many, max: 2_000), (0..<100).map { "m" + String(format: "%05d", $0) })
        // A sender over a quarter gives up its oldest until it is down to a quarter; then the oldest of all go.
        let honest = held("h", 1_800, from: 1_000) { "sender-\($0 % 600)" }, flood = held("f", 2_500, from: 10_000) { _ in "flooder" }
        let drop = Set(StoreCap.everyone(honest + flood, max: 2_000))
        XCTAssertEqual(drop.count, 2_300)
        XCTAssertEqual(flood.filter { !drop.contains($0.id) }.count, 500); XCTAssertEqual(honest.filter { !drop.contains($0.id) }.count, 1_500)
        XCTAssertTrue((0..<300).allSatisfy { drop.contains("h" + String(format: "%05d", $0)) })
        // This phone's own packets, the oldest of all here, stay while anything else can go.
        let own = held("o", 50, from: 10, own: true) { _ in "me" }
        let kept = StoreCap.everyone(own + many, max: 2_000)
        XCTAssertEqual(kept.count, 150); XCTAssertFalse(kept.contains { $0.hasPrefix("o") })
        XCTAssertEqual(StoreCap.everyone(own, max: 48), ["o00000", "o00001"]) // only own left: the oldest of them
    }

    // MARK: - 8. The Everyone introduction goes out only for someone who posts there

    func testAPhoneIntroducesItselfOnEveryoneOnlyWhenItsUserPostsThere() {
        let now = t0, day: Int64 = 24 * 3_600_000
        XCTAssertFalse(PublicIntro.wanted(writing: false, lastOwnPost: nil, now: now), "never posted: nothing at app start")
        XCTAssertTrue(PublicIntro.wanted(writing: true, lastOwnPost: nil, now: now), "writing now")
        XCTAssertTrue(PublicIntro.wanted(writing: false, lastOwnPost: now - 6 * day, now: now), "a post of theirs is still shown")
        XCTAssertFalse(PublicIntro.wanted(writing: false, lastOwnPost: now - 7 * day, now: now), "their last post is gone")
    }
}
