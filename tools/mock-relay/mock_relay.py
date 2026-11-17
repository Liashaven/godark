#!/usr/bin/env python3
"""A hostile Nostr relay for testing GoDark. It binds to 127.0.0.1 only and never contacts anything else.

Debug builds reach it through their relay override (Android: `adb reverse tcp:PORT tcp:PORT`, then
`--es relays ws://127.0.0.1:PORT`; iPhone Simulator: launch arguments `relays ws://127.0.0.1:PORT`).

It behaves like an honest NIP-01 relay until told otherwise, and always logs the metadata a relay sees, as JSON lines.
It holds no group key: every attack here is one a real relay operator could carry out.

  mock_relay.py --port 7447 --log out.jsonl [attacks]

Only the standard library. WebSocket per RFC 6455, text and control frames, no extensions.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import os
import random
import ssl
import struct
import time

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
KIND = 3871
MARKER = 0xB3
HOST = "127.0.0.1"  # never configurable: this tool must not be reachable from anywhere else


def frame(op, payload, fin=True):
    b0 = (0x80 if fin else 0) | op
    n = len(payload)
    if n < 126:
        head = bytes([b0, n])
    elif n < 65536:
        head = bytes([b0, 126]) + struct.pack(">H", n)
    else:
        head = bytes([b0, 127]) + struct.pack(">Q", n)
    return head + payload


def packet_bytes(pid, ts, ttl, cipher):
    return bytes([MARKER]) + pid + struct.pack(">q", ts) + bytes([ttl]) + cipher


def parse_packet(content):
    try:
        raw = base64.b64decode(content, validate=True)
    except Exception:
        return None
    if len(raw) < 19 or raw[0] != MARKER:
        return None
    return {"id": raw[1:9], "ts": struct.unpack(">q", raw[9:17])[0], "ttl": raw[17], "cipher": raw[18:]}


def make_event(pid, ts, ttl, cipher, tag=None, created=None, relay_key=b"\x11" * 32):
    """An event only a relay would make: apps must not trust anything about it, and its signature is not valid."""
    created = int(time.time()) if created is None else created
    content = base64.b64encode(packet_bytes(pid, ts, ttl, cipher)).decode()
    mailbox = pid[:2].hex()
    tags = [["t", tag or ("dp1-" + mailbox)], ["x", pid.hex()], ["expiration", str(created + 604800)]]
    pub = relay_key.hex()
    ser = json.dumps([0, pub, created, KIND, tags, content], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(ser.encode()).hexdigest()
    return {"id": eid, "pubkey": pub, "created_at": created, "kind": KIND, "tags": tags, "content": content, "sig": "00" * 64}


def matches(ev, f):
    if "kinds" in f and ev.get("kind") not in f["kinds"]:
        return False
    if "since" in f and ev.get("created_at", 0) < f["since"]:
        return False
    if "until" in f and ev.get("created_at", 0) > f["until"]:
        return False
    tags = {}
    for t in ev.get("tags", []):
        if len(t) >= 2:
            tags.setdefault(t[0], set()).add(t[1])
    for key, wanted in f.items():
        if key.startswith("#") and not (tags.get(key[1:], set()) & set(wanted)):
            return False
    return True


class Conn:
    def __init__(self, reader, writer, cid):
        self.r, self.w, self.cid = reader, writer, cid
        self.subs = {}
        self.opened = time.time()
        self.alive = True

    async def send(self, text):
        await self.raw(frame(1, text.encode()))

    async def raw(self, data):
        if not self.alive:
            return
        try:
            self.w.write(data)
            await self.w.drain()
        except (ConnectionError, RuntimeError):
            self.alive = False

    def close(self):
        self.alive = False
        try:
            self.w.close()
        except Exception:
            pass


class Relay:
    def __init__(self, a):
        self.a = a
        self.events = []
        self.conns = {}
        self.next_id = 0
        self.log_file = open(a.log, "a", buffering=1) if a.log else None
        self.flooded = set()

    def log(self, kind, **kv):
        line = json.dumps({"t": round(time.time(), 3), "kind": kind, **kv}, sort_keys=True)
        if self.log_file:
            self.log_file.write(line + "\n")

    # --- WebSocket ---

    async def handshake(self, r, w):
        data = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 15)
        headers = {}
        for line in data.decode("latin1").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        key = headers.get("sec-websocket-key")
        if not key:
            return None
        accept = base64.b64encode(hashlib.sha1(key.encode() + GUID).digest()).decode()
        nl = "\n" if self.a.lf_headers else "\r\n"  # clients also accept bare line feeds
        if self.a.interim:  # interim answers before the real one
            w.write(f"HTTP/1.1 100 Continue{nl}{nl}HTTP/1.1 103 Early Hints{nl}Link: x{nl}{nl}".encode())
        w.write(nl.join(["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade",
                         f"Sec-WebSocket-Accept: {accept}", "", ""]).encode())
        await w.drain()
        return headers

    async def read_message(self, c):
        buf = bytearray()
        while True:
            head = await c.r.readexactly(2)
            fin, op, masked, n = head[0] & 0x80, head[0] & 0x0F, head[1] & 0x80, head[1] & 0x7F
            if n == 126:
                n = struct.unpack(">H", await c.r.readexactly(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", await c.r.readexactly(8))[0]
            mask = await c.r.readexactly(4) if masked else b"\0\0\0\0"
            body = bytearray(await c.r.readexactly(n))
            for i in range(n):
                body[i] ^= mask[i % 4]
            if op == 8:
                return None
            if op == 9:
                await c.raw(frame(10, bytes(body)))
                continue
            if op == 10:
                continue
            buf += body
            if fin:
                return buf.decode("utf-8", "replace")

    # --- NIP-01 ---

    async def on_event(self, c, ev):
        pkt = parse_packet(ev.get("content", ""))
        self.log("event_in", conn=c.cid, event=ev.get("id", "")[:16], pubkey=ev.get("pubkey", "")[:16],
                 created_at=ev.get("created_at"), ev_kind=ev.get("kind"), tags=[t[:2] for t in ev.get("tags", [])][:3],
                 packet_id=pkt["id"].hex() if pkt else None, packet_ts=pkt["ts"] if pkt else None,
                 ttl=pkt["ttl"] if pkt else None, cipher_len=len(pkt["cipher"]) if pkt else None)
        a = self.a
        if a.reject:
            await c.send(json.dumps(["OK", ev.get("id"), False, a.reject]))
            return
        await c.send(json.dumps(["OK", ev.get("id"), True, ""]))
        if a.fake_ok:
            return  # says it stored the event; nobody will ever get it
        if ev.get("kind") != KIND or pkt is None:
            return
        tag = next((t[1] for t in ev.get("tags", []) if len(t) > 1 and t[0] == "t"), "")
        if tag in a.drop_tag or (a.drop_pct and random.random() * 100 < a.drop_pct):
            self.log("attack_drop", packet_id=pkt["id"].hex(), tag=tag)
            return
        if a.junk_race:  # under the same id, before the real packet: tries to use up the copies a phone accepts
            for _ in range(a.junk_race):
                junk = os.urandom(len(pkt["cipher"]))
                await self.fanout(make_event(pkt["id"], pkt["ts"], pkt["ttl"], junk, tag), skip=None)
            self.log("attack_junk_race", packet_id=pkt["id"].hex(), copies=a.junk_race)
        if a.tamper:
            bad = bytearray(pkt["cipher"])
            bad[len(bad) // 2] ^= 0x01
            ev = make_event(pkt["id"], pkt["ts"], pkt["ttl"], bytes(bad), tag)
            self.log("attack_tamper", packet_id=pkt["id"].hex())
        if a.tamper_ts:
            ev = make_event(pkt["id"], pkt["ts"] - 3_600_000, pkt["ttl"], pkt["cipher"], tag)
            self.log("attack_tamper_ts", packet_id=pkt["id"].hex())
        self.events.append(ev)
        if a.delay:
            await asyncio.sleep(a.delay)
        await self.fanout(ev, skip=c if not a.echo else None)
        for k in range(a.replay):  # the same packet again, as new events
            await asyncio.sleep(a.replay_gap)
            again = make_event(pkt["id"], pkt["ts"], pkt["ttl"], pkt["cipher"], tag)
            self.log("attack_replay", packet_id=pkt["id"].hex(), n=k + 1)
            await self.fanout(again, skip=None)

    async def fanout(self, ev, skip):
        for c in list(self.conns.values()):
            if c is skip:
                continue
            for sid, filters in list(c.subs.items()):
                if any(matches(ev, f) for f in filters):
                    await c.send(json.dumps(["EVENT", sid, ev]))
                    break

    async def on_req(self, c, sid, filters):
        self.log("req", conn=c.cid, sub=sid[:12], filters=filters)
        c.subs[sid] = filters
        a = self.a
        if a.garbage:
            await self.send_garbage(c, sid)
        if a.huge and not getattr(c, "huged", False):
            c.huged = True
            asyncio.ensure_future(self.send_huge(c))
        if a.fake_eose:
            await c.send(json.dumps(["EOSE", sid]))
            return
        if a.endless_pages and sid.startswith("cu"):
            mailbox = bytes.fromhex(filters[0]["#t"][0][4:])
            until = filters[0].get("until", int(time.time()))
            for _ in range(500):
                pid = mailbox + os.urandom(6)
                ev = make_event(pid, int(time.time() * 1000), 16, os.urandom(120), created=until)
                await c.send(json.dumps(["EVENT", sid, ev]))
            await c.send(json.dumps(["EOSE", sid]))
            self.log("attack_endless_page", conn=c.cid, sub=sid[:12])
            return
        sent = 0
        for f in filters:
            hits = [e for e in self.events if matches(e, f)]
            for ev in hits[-int(f.get("limit", 500)):]:
                await c.send(json.dumps(["EVENT", sid, ev]))
                sent += 1
        await c.send(json.dumps(["EOSE", sid]))
        self.log("eose", conn=c.cid, sub=sid[:12], sent=sent)
        if (a.flood or a.same_id) and (not sid.startswith(("cu", "have"))) and c.cid not in self.flooded:
            self.flooded.add(c.cid)
            asyncio.ensure_future(self.flood(c, sid, filters))

    async def flood(self, c, sid, filters):
        """Unique packets with valid headers in this phone's mailboxes. Unreadable, but the phone can't know that first."""
        a = self.a
        tags = filters[0].get("#t", ["dp1-9576"])
        boxes = [bytes.fromhex(t[4:]) for t in tags]
        started = time.time()
        fixed = random.choice(boxes) + os.urandom(6)  # --same-id: one id, different content every time
        for i in range(a.same_id or a.flood):
            if not c.alive:
                break
            pid = fixed if a.same_id else random.choice(boxes) + os.urandom(6)
            ev = make_event(pid, int(time.time() * 1000), 16, os.urandom(a.flood_size))
            await c.send(json.dumps(["EVENT", sid, ev]))
            if a.flood_rate:
                await asyncio.sleep(1.0 / a.flood_rate)
        self.log("attack_flood_done", conn=c.cid, sent=a.same_id or a.flood, seconds=round(time.time() - started, 2))

    async def send_huge(self, c):
        """One text message of a.huge MiB, in a single frame, as fast as the socket takes it."""
        size = self.a.huge * 1024 * 1024
        body_size = size - len('["NOTICE",""]')
        head = frame(1, b"")[:1] + bytes([127]) + struct.pack(">Q", size)
        await c.raw(head + b'["NOTICE","')
        chunk = b"A" * (1 << 20)
        left = body_size
        started = time.time()
        while left > 0 and c.alive:
            n = min(left, len(chunk))
            await c.raw(chunk[:n])
            left -= n
        await c.raw(b'"]')
        self.log("attack_huge_frame", conn=c.cid, mib=self.a.huge, complete=left <= 0, seconds=round(time.time() - started, 2))

    async def send_garbage(self, c, sid):
        items = [
            b"not json", b"[]", b"{}", b"null", b'["EVENT"]', b'["EVENT",1,2]', b'["OK"]', b'["EOSE"]', b'["CLOSED"]',
            b'["EVENT","x",{"kind":3871}]',
            b'["EVENT","x",{"kind":"3871","content":123,"id":null}]',
            b'["EVENT","x",{"kind":3871,"content":"////","id":"a","pubkey":"b","created_at":-5}]',
            b'["EVENT","x",{"kind":3871,"content":"' + base64.b64encode(b"\xb3" * 18) + b'","id":"a","pubkey":"b","created_at":1e400}]',
            b"[" * 200000, b'{"a":' * 200000,
            b'["OK","' + b"f" * 64 + b'",true,"' + b"x" * 200000 + b'"]',
            b'["NOTICE","\xed\xa0\x80"]', b"\xff\xfe\xfd", b'["EVENT","\x00",{"kind":3871}]',
        ]
        for data in items:
            await c.raw(frame(1, data))
        self.log("attack_garbage", conn=c.cid, frames=len(items))

    async def serve(self, reader, writer):
        self.next_id += 1
        c = Conn(reader, writer, self.next_id)
        peer = writer.get_extra_info("peername")
        try:
            headers = await self.handshake(reader, writer)
            if headers is None:
                return
            self.conns[c.cid] = c
            self.log("connect", conn=c.cid, peer=str(peer[0]), user_agent=headers.get("user-agent", ""),
                     extensions=headers.get("sec-websocket-extensions", ""))
            if self.a.notice_flood:
                asyncio.ensure_future(self.notices(c))
            if self.a.bounce:
                asyncio.get_event_loop().call_later(self.a.bounce, c.close)
            while True:
                text = await self.read_message(c)
                if text is None:
                    break
                try:
                    msg = json.loads(text)
                except ValueError:
                    continue
                if not isinstance(msg, list) or not msg:
                    continue
                if msg[0] == "EVENT" and len(msg) > 1:
                    await self.on_event(c, msg[1])
                elif msg[0] == "REQ" and len(msg) > 2:
                    await self.on_req(c, msg[1], msg[2:])
                elif msg[0] == "CLOSE" and len(msg) > 1:
                    c.subs.pop(msg[1], None)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            self.conns.pop(c.cid, None)
            self.log("disconnect", conn=c.cid, seconds=round(time.time() - c.opened, 2))
            c.close()

    async def notices(self, c):
        for i in range(self.a.notice_flood):
            await c.send(json.dumps(["NOTICE", "n" * 1000]))
        self.log("attack_notice_flood", conn=c.cid, sent=self.a.notice_flood)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, default=7447)
    p.add_argument("--log", help="append a JSON line per thing the relay saw or did")
    p.add_argument("--tamper", action="store_true", help="flip one bit in every cipher")
    p.add_argument("--tamper-ts", action="store_true", help="change every packet's ts by one hour")
    p.add_argument("--junk-race", type=int, default=0, help="send N random packets under each id before the real one")
    p.add_argument("--replay", type=int, default=0, help="deliver every packet N more times as new events")
    p.add_argument("--replay-gap", type=float, default=2.0)
    p.add_argument("--drop-tag", action="append", default=[], help="never deliver this mailbox tag, e.g. dp1-6a44")
    p.add_argument("--drop-pct", type=float, default=0)
    p.add_argument("--delay", type=float, default=0, help="hold every event this many seconds")
    p.add_argument("--echo", action="store_true", help="send events back to the phone that posted them")
    p.add_argument("--fake-ok", action="store_true", help="answer OK true but store and deliver nothing")
    p.add_argument("--reject", help="refuse every event with this reason")
    p.add_argument("--fake-eose", action="store_true", help="answer EOSE at once, with no stored events")
    p.add_argument("--endless-pages", action="store_true", help="answer every catch-up with a full page of junk")
    p.add_argument("--flood", type=int, default=0, help="send N unique junk packets after the live subscription")
    p.add_argument("--flood-rate", type=float, default=0, help="packets per second; 0 = as fast as the socket takes them")
    p.add_argument("--flood-size", type=int, default=120, help="cipher bytes per flood packet")
    p.add_argument("--same-id", type=int, default=0, help="send N packets that share one id, with different content")
    p.add_argument("--lf-headers", action="store_true", help="end the HTTP answer's lines with bare line feeds")
    p.add_argument("--interim", action="store_true", help="send 1xx answers before the 101")
    p.add_argument("--huge", type=int, default=0, help="send one text message of N MiB in a single frame")
    p.add_argument("--notice-flood", type=int, default=0)
    p.add_argument("--garbage", action="store_true", help="send malformed JSON and frames")
    p.add_argument("--bounce", type=float, default=0, help="drop each connection after N seconds")
    p.add_argument("--tls", nargs=2, metavar=("CERT", "KEY"), help="serve wss:// with this certificate")
    a = p.parse_args()
    relay = Relay(a)
    tls = None
    if a.tls:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(a.tls[0], a.tls[1])

    async def run():
        server = await asyncio.start_server(relay.serve, HOST, a.port, limit=1 << 22, ssl=tls)
        print(f"mock relay on {'wss' if tls else 'ws'}://{HOST}:{a.port}", flush=True)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
