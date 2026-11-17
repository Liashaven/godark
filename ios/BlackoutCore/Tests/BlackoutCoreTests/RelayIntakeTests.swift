import XCTest
import CryptoKit
@testable import BlackoutCore

/// What a relay, or someone posting to a relay, could do to the phone (audit of 2026-11). Each of these failed before
/// its fix; Android's RelayIntakeTest checks the same (and, there only, OkHttp's WebSocket compression). Dummy keys and
/// packets only.
final class RelayIntakeTests: XCTestCase {
    private func key(_ label: String) -> Data { Data(SHA256.hash(data: Data(label.utf8))) }
    private var poster: Data { key("dummy poster") }
    private var second: Data { key("dummy second poster") }

    private func frame(_ e: [String: Any]) -> String {
        "[\"EVENT\",\"s\"," + String(decoding: try! JSONSerialization.data(withJSONObject: e), as: UTF8.self) + "]"
    }
    /// The event's id as NIP-01 computes it from the fields it has now.
    private func idOf(_ e: [String: Any]) -> String {
        Nostr.eventId(pubkey: e["pubkey"] as! String, createdAt: (e["created_at"] as! NSNumber).int64Value, kind: e["kind"] as! Int,
                      tags: e["tags"] as! [[String]], content: e["content"] as! String)
    }
    /// A correctly signed event of the app's kind with any tags: what anyone can post to a relay.
    private func signedEvent(_ p: Packet, _ secret: Data, created: Int64, tags: [[String]]) -> [String: Any] {
        var e: [String: Any] = ["pubkey": Hex.encode(Schnorr.publicKey(secret)), "created_at": created, "kind": Nostr.kind, "tags": tags,
                                "content": p.encode().base64EncodedString()]
        let id = idOf(e)
        e["id"] = id; e["sig"] = Hex.encode(Schnorr.sign(secret: secret, message: Hex.decode(id)))
        return e
    }
    /// The event the app itself posts.
    private func event(_ p: Packet, _ secret: Data, _ now: Int64) -> [String: Any] {
        Nostr.event(p, pubkey: Hex.encode(Schnorr.publicKey(secret)), now: now) { Schnorr.sign(secret: secret, message: $0) }
    }
    private func received(_ e: [String: Any], file: StaticString = #filePath, line: UInt = #line) throws -> Nostr.Received {
        try XCTUnwrap(Nostr.received(frame(e)), "not taken as a packet", file: file, line: line)
    }

    // MARK: - A copy of a packet on the relays ends posting only if the packet's recipients get that copy

    private let nowMs: Int64 = 1_800_000_000_000
    private var nowS: Int64 { nowMs / 1000 }
    private var bridged: Packet { Packet(id: "a8d00000000000c3", ts: nowMs - 10 * 60_000, ttl: 15, cipher: Data(repeating: 5, count: 100)) }
    private let box = ["t", "dp1-a8d0"]
    private var x: [String] { ["x", bridged.id] }
    private func kept(from created: Int64) -> [String] { ["expiration", String(created + Nostr.keepSeconds)] }

    /// Someone else's packet through the outbox as RelayScope does it, with `copy` as an answer to the #x lookup. True
    /// if this phone still posts it.
    private func stillPosted(_ copy: [String: Any]?) throws -> Bool {
        let o = RelayOutbox(now: { self.nowMs }, jitter: { 0 })
        o.offer(bridged, mine: false)
        let batch = o.toCheck(50)
        XCTAssertEqual(batch.map(\.id), [bridged.id])
        let marked = try copy.flatMap { try o.fromRelay(received($0)) }
        let found = o.checked(batch)
        let still = marked == nil && found.isEmpty && !o.isSent(bridged.id) && o.next(bridged: true)?.packet.id == bridged.id
        if !still { o.offer(bridged, mine: false); XCTAssertEqual(o.queued, 0, "counted as on the relays: never queued again") }
        return still
    }

    func testACopyTheRecipientsDontGetDoesNotEndPosting() throws {
        XCTAssertTrue(try stillPosted(nil), "control: no relay has it")
        XCTAssertFalse(try stillPosted(event(bridged, poster, nowS)), "control: the event the app posts ends posting")
        XCTAssertFalse(try stillPosted(event(bridged, poster, Nostr.blurred(nowS - 300))), "control: dated as the app dates it")
        XCTAssertFalse(try stillPosted(signedEvent(bridged, poster, created: nowS, tags: [box, x])), "control: without an expiration it is kept for good")

        XCTAssertTrue(try stillPosted(signedEvent(bridged, poster, created: nowS, tags: [x])), "only the x tag: no subscription returns it")
        XCTAssertTrue(try stillPosted(signedEvent(bridged, poster, created: nowS, tags: [["t", "dp1-0794"], x, kept(from: nowS)])), "another mailbox's tag")
        XCTAssertTrue(try stillPosted(signedEvent(bridged, poster, created: nowS, tags: [["t", "a8d0"], x, kept(from: nowS)])), "the tag without its prefix")
        XCTAssertTrue(try stillPosted(signedEvent(bridged, poster, created: nowS, tags: [box, x, ["expiration", String(nowS + 60)]])), "gone in a minute")
        XCTAssertTrue(try stillPosted(signedEvent(bridged, poster, created: nowS, tags: [box, x, kept(from: nowS), ["expiration", String(nowS + 60)]])), "a second expiration, gone in a minute")
        XCTAssertTrue(try stillPosted(signedEvent(bridged, poster, created: nowS, tags: [box, x, ["expiration", "never"]])), "an expiration that is no number")
        XCTAssertTrue(try stillPosted(signedEvent(bridged, poster, created: nowS, tags: [box, x, ["expiration"]])), "an expiration without a value")
        let old = nowS - 6 * 24 * 3600
        XCTAssertTrue(try stillPosted(signedEvent(bridged, poster, created: old, tags: [box, x, kept(from: old)])), "dated days before the packet: a catch-up doesn't ask that far back")
        var bad = signedEvent(bridged, poster, created: nowS, tags: [box, x])
        bad["tags"] = [box, ["x", 7]] as [[Any]]
        XCTAssertTrue(try stillPosted(bad), "tags that aren't strings")
    }

    func testWhatReachesTheRecipientsIsSaidForEachEvent() throws {
        XCTAssertTrue(try received(event(bridged, poster, nowS)).reaches)
        XCTAssertFalse(try received(signedEvent(bridged, poster, created: nowS, tags: [x])).reaches)
        let edge = bridged.ts / 1000 - Nostr.sinceMarginSeconds
        XCTAssertTrue(try received(signedEvent(bridged, poster, created: edge, tags: [box, x, kept(from: edge)])).reaches)
        XCTAssertFalse(try received(signedEvent(bridged, poster, created: edge - 1, tags: [box, x, kept(from: edge - 1)])).reaches)
        // A date at the end of time must not end the app (Swift traps on overflow).
        XCTAssertTrue(try received(signedEvent(bridged, poster, created: .max, tags: [box, x, ["expiration", String(Int64.max)]])).reaches)
        XCTAssertFalse(try received(signedEvent(bridged, poster, created: .max, tags: [box, x, ["expiration", "5"]])).reaches)
        let farBack = Packet(id: "a8d00000000000c5", ts: .min, ttl: 15, cipher: Data(repeating: 5, count: 100))
        XCTAssertTrue(try received(signedEvent(farBack, poster, created: 0, tags: [box, ["x", farBack.id]])).reaches)
    }

    func testAnEchoWithoutTheMailboxTagDoesNotMakeAnOwnMessageSent() throws {
        let o = RelayOutbox(now: { self.nowMs }, jitter: { 0 })
        let mine = Packet(id: "a8d00000000000c4", ts: nowMs - 1_000, ttl: 16, cipher: Data(repeating: 6, count: 100))
        o.offer(mine, mine: true)
        let n = try XCTUnwrap(o.next(bridged: false))
        o.posted(eventId: "ev1", n.packet, fromOwn: n.fromOwn, relays: ["r1"])
        XCTAssertNil(o.fromRelay(try received(signedEvent(mine, second, created: nowS, tags: [["x", mine.id]]))))
        XCTAssertFalse(o.isSent(mine.id))
        XCTAssertEqual(o.fromRelay(try received(event(mine, poster, nowS))), mine.id) // the real one, as the live subscription returns it
        XCTAssertTrue(o.isSent(mine.id))
    }

    // MARK: - An event id and author are 32 bytes of hex each, never more

    private func rawEvent(_ packetId: String, id: Any, pubkey: Any) -> String {
        frame(["id": id, "pubkey": pubkey, "created_at": 1, "kind": Nostr.kind, "tags": [[String]](),
               "content": Packet(id: packetId, ts: nowMs, ttl: 16, cipher: Data(count: 98)).encode().base64EncodedString()])
    }

    func testAnEventIdOrAuthorOfAnyOtherLengthOrFormIsRefused() throws {
        let id = String(repeating: "ab", count: 32), pub = String(repeating: "cd", count: 32)
        let ok = try XCTUnwrap(Nostr.received(rawEvent("0000000000000001", id: id, pubkey: pub)))
        XCTAssertEqual(ok.eventId, id); XCTAssertEqual(ok.pubkey, pub)

        let long = String(repeating: "a", count: 1_000_000)
        XCTAssertLessThan(rawEvent("0000000000000002", id: long, pubkey: "b").utf8.count, 1 << 20, "under the 1 MiB message limit: nothing before Nostr.received stops it")
        XCTAssertNil(Nostr.received(rawEvent("0000000000000002", id: long, pubkey: pub)), "an id of 1,000,000 characters")
        XCTAssertNil(Nostr.received(rawEvent("0000000000000003", id: id, pubkey: long)), "an author of 1,000,000 characters")
        let ab31 = String(repeating: "ab", count: 31)
        let bad: [Any] = ["", "a", ab31 + "a", id + "a", id + id, String(repeating: "AB", count: 32), String(repeating: "zz", count: 32), ab31 + "a ", ab31 + "éé", 7, [String]()]
        for b in bad {
            XCTAssertNil(Nostr.received(rawEvent("0000000000000004", id: b, pubkey: pub)), "id \(b)")
            XCTAssertNil(Nostr.received(rawEvent("0000000000000005", id: id, pubkey: b)), "author \(b)")
        }
    }

    // MARK: - A report names an event that really carried the reported packet and is really its author's

    private let now: Int64 = 1_793_990_000
    private var shown: Packet { Packet(id: "9576000000000001", ts: 1_793_990_000_000, ttl: 16, cipher: Data(repeating: 1, count: 120)) } // the Public message the user reports

    func testAReportNeverNamesAnEventOrAuthorTheRelayMadeUp() throws {
        let real = event(shown, poster, now)
        // The frame of the audit: id and author replaced by the relay, signature left as it was.
        var forged = real
        forged["id"] = String(repeating: "a", count: 64); forged["pubkey"] = String(repeating: "b", count: 64)
        let r = try received(forged) // still a packet for the router
        XCTAssertNil(r.subject, "its id is not the hash of its fields")
        let s = ReportSubjects()
        s.note(relay: "wss://hostile", r)
        XCTAssertFalse(s.knows(shown.id)); XCTAssertNil(s.of(MeshRouter.key(shown)))

        // A relay can hash, but it can't sign for someone else: an account that has nothing to do with it as the author, under the right id.
        var uninvolved = real
        uninvolved["pubkey"] = Hex.encode(Schnorr.publicKey(key("dummy uninvolved account")))
        uninvolved["id"] = idOf(uninvolved)
        let u = try received(uninvolved)
        XCTAssertNotNil(u.subject)
        s.note(relay: "wss://hostile", u)
        XCTAssertTrue(s.knows(shown.id))
        XCTAssertNil(s.of(MeshRouter.key(shown)), "not signed by the author it names: the report waits")
        XCTAssertFalse(s.knows(shown.id), "and that event is forgotten")

        // The made-up event first, the real one from another relay: the real one is named.
        s.note(relay: "wss://hostile", u); s.note(relay: "wss://honest", try received(real))
        let named = try XCTUnwrap(s.of(MeshRouter.key(shown)))
        XCTAssertEqual(named.eventId, real["id"] as? String); XCTAssertEqual(named.pubkey, real["pubkey"] as? String)
        let reporter = key("dummy reporting phone")
        let report = Nostr.report(eventId: named.eventId, author: named.pubkey, pubkey: Hex.encode(Schnorr.publicKey(reporter)), now: now + 100) { Schnorr.sign(secret: reporter, message: $0) }
        XCTAssertEqual(report["tags"] as? [[String]], [["e", real["id"] as! String, "other"], ["p", real["pubkey"] as! String]])
    }

    func testASignatureThatIsNotOneGivesNoReportSubject() throws {
        let e = event(shown, poster, now)
        let sigs: [Any] = ["", String(repeating: "ab", count: 63), String(repeating: "AB", count: 64), String(repeating: "a", count: 500_000), 7]
        for sig in sigs { var f = e; f["sig"] = sig; XCTAssertNil(try received(f).subject, "sig \(String(describing: sig).prefix(70))") }
        var none = e; none["sig"] = nil
        XCTAssertNil(try received(none).subject, "no signature")
        XCTAssertNotNil(try received(e).subject)
        XCTAssertFalse(Nostr.signed(Nostr.Subject(eventId: e["id"] as! String, pubkey: e["pubkey"] as! String, sig: String(repeating: "00", count: 64))))
        XCTAssertFalse(Nostr.signed(Nostr.Subject(eventId: "x", pubkey: "y", sig: "z")))
    }

    func testAnotherPacketUnderTheSameIdNeverStandsInForTheOneShown() throws {
        let first = try received(event(shown, poster, now))
        let decoy = Packet(id: shown.id, ts: shown.ts, ttl: 16, cipher: Data(repeating: 2, count: 120)) // anyone can post any packet under a packet id they have seen
        let later = try received(event(decoy, second, now))
        XCTAssertEqual(first.packet.id, later.packet.id); XCTAssertNotEqual(first.eventId, later.eventId)
        for order in [[first, later], [later, first]] {
            let s = ReportSubjects()
            order.forEach { s.note(relay: "r1", $0) }; order.forEach { s.note(relay: "r2", $0) }
            XCTAssertEqual(s.of(MeshRouter.key(shown))?.eventId, first.eventId, "whichever came last")
            XCTAssertEqual(s.of(MeshRouter.key(shown))?.pubkey, first.pubkey)
            XCTAssertEqual(s.of(MeshRouter.key(decoy))?.eventId, later.eventId)
        }
        // The same packet posted again by someone else: the first event for it stays.
        let s = ReportSubjects()
        s.note(relay: "r1", first); s.note(relay: "r1", try received(event(shown, second, now + 1024)))
        XCTAssertEqual(s.of(MeshRouter.key(shown))?.eventId, first.eventId)
    }

    func testOnlyPublicPacketsAreKeptForReportsAndOnlySoMany() throws {
        XCTAssertNil(try received(event(bridged, poster, nowS)).subject, "a group's packet")
        let s = ReportSubjects(max: 3)
        let all = (1...4).map { i in Packet(id: "957600000000000\(i)", ts: shown.ts, ttl: 16, cipher: Data(repeating: UInt8(i), count: 120)) }
        try all.forEach { s.note(relay: "r1", try received(event($0, poster, now))) }
        XCTAssertEqual(s.count, 3)
        XCTAssertFalse(s.knows(all[0].id), "the oldest made room"); XCTAssertNil(s.of(MeshRouter.key(all[0])))
        XCTAssertTrue(s.knows(all[3].id)); XCTAssertNotNil(s.of(MeshRouter.key(all[3])))
        // One relay gets one place per packet, whatever it sends.
        let one = ReportSubjects()
        for i in 0..<5 { one.note(relay: "r1", try received(event(shown, key("dummy \(i)"), now))) }
        one.note(relay: "r2", try received(event(shown, poster, now)))
        XCTAssertEqual(one.count, 1); XCTAssertEqual(one.of(MeshRouter.key(shown))?.pubkey, Hex.encode(Schnorr.publicKey(key("dummy 0"))))
    }
}
