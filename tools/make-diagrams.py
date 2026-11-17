#!/usr/bin/env python3
"""Draws the README banner and diagrams as standalone SVG files in docs/diagrams/.

    python3 tools/make-diagrams.py

GitHub shows an SVG in a README as an image: no scripts, no web fonts, nothing loaded from elsewhere. So every
file here is self-contained and uses fonts each system already has. Colours are the website's (site/style.css):
black paper, white ink, grey rules, and the "safe" green as the one accent.
"""
import base64
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent.parent / "docs" / "diagrams"
INK, MUTED, SOFT, RULE, FAINT, ACCENT = "#FFFFFF", "#A3A3A3", "#8A8A8A", "#595A5A", "#272727", "#33D64A"
SERIF = "Georgia,'Times New Roman',serif"
SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"

STYLE = f"""
.t{{font-family:{SERIF};font-size:34px;fill:{INK}}}
.n{{font-family:{SANS};font-size:18px;font-weight:600;fill:{INK}}}
.s{{font-family:{MONO};font-size:13.5px;fill:{MUTED}}}
.e{{font-family:{MONO};font-size:11.5px;letter-spacing:.16em;fill:{SOFT}}}
.box{{fill:#0C0C0C;stroke:{RULE};stroke-width:1}}
.focal{{fill:rgba(51,214,74,.07);stroke:{ACCENT};stroke-width:1.2}}
.a{{stroke:{MUTED};stroke-width:1.2;fill:none}}
.d{{stroke:{RULE};stroke-width:1;fill:none;stroke-dasharray:3 5}}
.g{{fill:{ACCENT}}}
"""


def svg(name, w, h, title, desc, body):
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
            f'aria-labelledby="t d"><title id="t">{escape(title)}</title><desc id="d">{escape(desc)}</desc>'
            f'<style>{STYLE}</style><defs>'
            f'<marker id="m" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
            f'<path d="M0 0L10 5L0 10z" fill="{MUTED}"/></marker>'
            f'<marker id="mg" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
            f'<path d="M0 0L10 5L0 10z" fill="{ACCENT}"/></marker></defs>'
            f'<rect x=".5" y=".5" width="{w - 1}" height="{h - 1}" rx="14" fill="#000" stroke="{FAINT}"/>')
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(head + "".join(body) + "</svg>\n", encoding="utf-8")
    print("wrote", OUT / name)


def text(x, y, s, cls, anchor="start", extra=""):
    return f'<text x="{x}" y="{y}" class="{cls}" text-anchor="{anchor}"{extra}>{escape(s)}</text>'


def box(x, y, w, h, eyebrow, name, subs, focal=False):
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" class="{"focal" if focal else "box"}"/>',
           text(x + 18, y + 28, eyebrow, "e"), text(x + 18, y + 58, name, "n")]
    out += [text(x + 18, y + 84 + 20 * i, s, "s") for i, s in enumerate(subs)]
    return "".join(out)


def arrow(x1, y1, x2, y2, green=False):
    style = f' style="stroke:{ACCENT}"' if green else ""
    return f'<path d="M{x1} {y1}L{x2} {y2}" class="a" marker-end="url(#{"mg" if green else "m"})"{style}/>'


def header(n, title):
    return text(40, 44, n, "e") + text(40, 84, title, "t")


def hero():
    b = [f'<text x="70" y="270" style="font-family:{SERIF};font-size:104px;fill:{INK}">GoDark</text>',
         f'<text x="74" y="322" style="font-family:{MONO};font-size:17px;fill:{MUTED}">'
         'Messaging for when the network is gone.</text>',
         f'<text x="74" y="354" style="font-family:{MONO};font-size:15px;fill:{SOFT}">'
         'Phone to phone · Android and iPhone · no account required</text>']
    logo = OUT / "logo-176.png"  # generated from the GoDark signal mark in brand/godark-mark.svg
    if logo.exists():
        data = base64.b64encode(logo.read_bytes()).decode("ascii")
        b.append(f'<image x="72" y="84" width="72" height="72" href="data:image/png;base64,{data}"/>')
    planes = [((800, 52), (1200, 52), (1238, 168), (762, 168), "PEOPLE"),
              ((790, 196), (1210, 196), (1248, 312), (752, 312), "SEALED PACKETS"),
              ((780, 340), (1220, 340), (1258, 444), (742, 444), "LINKS")]
    for (a, b_, c, d, label) in planes:
        b.append(f'<path d="M{a[0]} {a[1]}L{b_[0]} {b_[1]}L{c[0]} {c[1]}L{d[0]} {d[1]}z" fill="#070707" stroke="{RULE}"/>')
        b.append(text(a[0] + 14, a[1] + 22, label, "e"))
    for (x1, y1, x2, y2) in [(762, 168, 790, 196), (1238, 168, 1210, 196), (752, 312, 780, 340), (1248, 312, 1220, 340)]:
        b.append(f'<path d="M{x1} {y1}L{x2} {y2}" class="d"/>')
    # people: phones that meet and pass a message on; the green path is one message
    nodes = [(850, 122), (930, 98), (1010, 128), (1090, 100), (1162, 130)]
    for (p, q) in zip(nodes, nodes[1:]):
        b.append(f'<path d="M{p[0]} {p[1]}L{q[0]} {q[1]}" stroke="{ACCENT}" stroke-width="1.2" fill="none"/>')
    for (p, q) in [(nodes[0], (900, 150)), ((900, 150), nodes[2]), (nodes[2], (1060, 150)), ((1060, 150), nodes[4])]:
        b.append(f'<path d="M{p[0]} {p[1]}L{q[0]} {q[1]}" class="d"/>')
    for i, (x, y) in enumerate(nodes + [(900, 150), (1060, 150)]):
        ends = i in (0, 4)
        b.append(f'<rect x="{x - 8}" y="{y - 13}" width="16" height="26" rx="3.5" fill="#000" '
                 f'stroke="{ACCENT if ends else INK}" stroke-width="1.2"/>')
    # sealed packets
    for i in range(6):
        x = 812 + i * 66
        b.append(f'<rect x="{x}" y="240" width="48" height="30" rx="4" fill="#000" stroke="{ACCENT if i == 2 else RULE}"/>')
        for k in range(3):
            b.append(f'<path d="M{x + 8} {249 + k * 6}h{32 - k * 8}" stroke="{ACCENT if i == 2 else RULE}"/>')
    b.append(text(812, 294, "encrypted and signed on the phone", "s", extra=' style="font-size:11.5px"'))
    # links
    for i, (label, w) in enumerate([("BLUETOOTH", 104), ("WI-FI", 70), ("LORA", 64), ("RELAYS · TOR", 124)]):
        x = [800, 916, 998, 1074][i]
        b.append(f'<rect x="{x}" y="386" width="{w}" height="30" rx="4" fill="#000" stroke="{RULE}"/>')
        b.append(text(x + w / 2, 405.5, label, "e", "middle", f' style="fill:{MUTED}"'))
    svg("hero.svg", 1280, 480, "GoDark. Messaging for when the network is gone.",
        "Three stacked layers: people passing a message along, sealed packets, and the links that carry them: "
        "Bluetooth, Wi-Fi, LoRa radio and internet relays through Tor.", b)


def message_path():
    y = 128
    b = [header("01 · DELIVERY", "How a message travels"),
         box(40, y, 180, 130, "YOUR PHONE", "You write", ["a message, photo,", "check-in or place"]),
         arrow(220, y + 65, 256, y + 65),
         box(260, y, 214, 130, "SEALED", "Encrypted, signed", ["with the group's", "current key"], focal=True),
         arrow(474, y + 65, 510, y + 65),
         box(514, y, 206, 130, "PACKET", "Sealed packet", ["id · time · hops left", "length is padded"])]
    links = ["Bluetooth LE", "Wi-Fi network", "LoRa radio", "Internet relays · Tor"]
    for i, name in enumerate(links):
        ly = 104 + i * 46
        b.append(f'<rect x="770" y="{ly}" width="216" height="36" rx="6" class="box"/>')
        b.append(text(788, ly + 23.5, name, "n", extra=' style="font-size:15.5px"'))
        b.append(arrow(720, y + 65, 766, ly + 18))
        b.append(f'<path d="M986 {ly + 18}L1012 {y + 65}" class="a"/>')  # the four meet, then one arrow goes on
    b += [text(770, 92, "ANY LINK THAT IS UP", "e"), arrow(1012, y + 65, 1036, y + 65),
          box(1040, y, 200, 130, "OTHER PHONES", "Carry it on", ["can't read it", "16 hops · 7 days"]),
          arrow(1140, y + 130, 1140, 322, green=True),
          box(1040, 326, 200, 130, "GROUP MEMBERS", "Open it", ["check the signature,", "show the message"], focal=True),
          f'<path d="M40 326h960v130h-960z" fill="none" stroke="{FAINT}"/>',
          text(62, 362, "Group messages don't need an account.", "s"),
          text(62, 392, "A phone that only carries a packet never holds the key to it.", "s"),
          text(62, 422, "Without internet, packets hop from phone to phone. With internet, they also cross", "s"),
          text(62, 442, "free public relays, through Tor unless you turn it off.", "s")]
    svg("message-path.svg", 1280, 496, "How a message travels",
        "You write a message. Your phone encrypts and signs it with the group's current key and wraps it in a sealed "
        "packet. The packet leaves over any link that is up: Bluetooth LE, a Wi-Fi network, a LoRa radio or internet "
        "relays through Tor. Other phones carry it on without being able to read it, for up to 16 hops and 7 days. "
        "Group members open it, check the signature and show the message.", b)


def who_sees_what():
    cards = [("GROUP MEMBERS", "Read the message", ["text, photos, check-ins", "and who signed it", "",
                                                    "Only phones that hold", "the group's current key."], True),
             ("PHONES THAT CARRY IT", "See a sealed packet", ["its id, time, hops left", "and size", "",
                                                             "Not the text."], False),
             ("INTERNET RELAYS", "See traffic", ["a 2-byte mailbox tag,", "timing and size;", "your address only if",
                                                 "Tor is switched off", "Not the text."], False),
             ("THE GROUP CODE ALONE", "Can only knock", ["The code opens the door:", "a request to join.",
                                                         "An admin must let", "you in.", "Not the text."], False)]
    b = [header("02 · PRIVACY BY DESIGN", "Who sees what")]
    for i, (e, n, subs, focal) in enumerate(cards):
        b.append(box(40 + i * 305, 124, 285, 214, e, n, subs, focal))
    b += [text(40, 380, "The Everyone channel is public by design: anyone with the app can read and post there.", "s"),
          text(40, 404, "This is the design. The Status section lists what has been checked on real phones and what has not.", "s")]
    svg("who-sees-what.svg", 1280, 436, "Who sees what, by design",
        "Group members read the message. Phones that carry a packet see its id, time, hops left and size, not the "
        "text. Internet relays see a 2-byte mailbox tag, timing and size, and your address only if Tor is switched "
        "off, not the text. Someone who has only the group code can ask to join; an admin must let them in. The "
        "Everyone channel is public by design.", b)


def group_keys():
    steps = [("Create", ["a random code and", "the first key;", "you are the admin"], False),
             ("Invite", ["a QR code or link", "that names the", "group's admins"], False),
             ("Join", ["an admin approves;", "a new key is sealed", "to every member"], False),
             ("Remove", ["a new code and key;", "the removed phone", "is not given them"], True),
             ("Every week", ["a fresh key; the old", "one is kept 7 days,", "then deleted"], False)]
    b = [header("03 · GROUPS", "How a group's keys change"),
         f'<path d="M100 196H1180" stroke="{RULE}" stroke-width="1.2" marker-end="url(#m)"/>']
    for i, (name, subs, focal) in enumerate(steps):
        x = 150 + i * 240
        b.append(f'<circle cx="{x}" cy="196" r="7" fill="#000" stroke="{ACCENT if focal else INK}" stroke-width="1.6"/>')
        if focal:
            b.append(f'<circle cx="{x}" cy="196" r="2.6" class="g"/>')
        b.append(text(x, 158, f"0{i + 1}", "e", "middle"))
        b.append(text(x, 246, name, "n", "middle"))
        b += [text(x, 274 + 20 * k, s, "s", "middle") for k, s in enumerate(subs)]
    b += [text(40, 372, "The group code only opens the door. Messages are sealed with a random key that changes,", "s"),
          text(40, 396, "sealed separately to each member, so knowing the code is not enough to read or write.", "s")]
    svg("group-keys.svg", 1280, 428, "How a group's keys change",
        "Creating a group makes a random code and the first key. An invite names the group's admins. To join, an "
        "admin approves and a new key is sealed to every member. Removing someone makes a new code and key that the "
        "removed phone is not given. Every week there is a fresh key; the old one is kept 7 days, then deleted.", b)


if __name__ == "__main__":
    hero(); message_path(); who_sees_what(); group_keys()
