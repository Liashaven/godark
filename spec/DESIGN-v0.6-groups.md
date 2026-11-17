# GoDark v0.6 design: joining, removing people, and keys that change

Changed since this was written (see FORMAT.md, which is the rule): joining needs an admin to let you in, group messages have a
key each, and new keys are sealed with ML-KEM as well as P-256.

Status: decided 2026-11-06 ("as simple as possible, secure like Signal"), built 2026-11-08. The wire rules now live in
spec/FORMAT.md ("Doors and epochs"), which wins if the two differ; this document keeps the reasoning and the risks.

## In short

Today the group code is the key to everything: anyone who has it, or gets it later, can read every message, past and
future, silently. v0.6 splits it in two:

- The **code** (what people type or scan) only opens the door: it lets a phone **ask to join**.
- The **group key** that encrypts messages is random, never typed or shown, and **changes whenever someone joins or
  is removed, and at least every week**. Members get each new key encrypted for them alone.

What that buys:

| Situation | Today (v0.5) | With v0.6 |
|---|---|---|
| A stranger gets the code (photo of the QR, overheard) | Reads everything, past and future, and nobody knows | Must join: everyone sees "Marco joined", and an admin can remove them |
| Someone new joins | Reads all the group's messages of the last week | Reads only what comes after they joined, like Signal |
| Someone recorded relay traffic, then gets the code | Reads all of it | Reads nothing: the code doesn't open messages |
| You remove someone | Not possible: you start a new group | Remove: the group gets a new key and a new code; they can't read what comes next |
| A phone is stolen and its keys copied | Reads everything, forever | Reads at most the last ~2 weeks, and is locked out at the next weekly key unless it's still a member |

What it costs:

- Joining needs a phone that's already in the group to be in reach (nearby, or online), usually for a few seconds.
  Today a phone can read with the code alone, even with nobody around.
- A phone that is away for more than a week asks to join again by itself when it comes back (it still has the code).
- Joining and new keys don't fit LoRa radio packets: they need Bluetooth, Wi-Fi or the internet once.
- A group's chat history lasts one to two weeks on each phone: when a key is deleted, the messages it opens go with it.
- More moving parts. This is a new design, not an existing standard like MLS (see "Why not MLS"), so it needs an
  outside review before GoDark says it protects people this way.

## How it works for people

- **Create a group:** the same as today.
- **Join:** scan the QR or type the code, as today. The screen says "Asking to join…", then "You're in". Standing next
  to the person who invites you, this takes a few seconds over Bluetooth or Wi-Fi.
- **The group sees it:** a line in the chat, "Marco joined", with Marco's emoji in his person card. There are no
  approval screens: like a Signal group link, the code is the invitation.
- **Admins:** whoever creates the group is its admin. An admin can make others admins ("Make admin" on their person
  card). Only admins can remove people. If every admin is gone, the group keeps working; nobody can remove anyone, and
  people can start a new group.
- **Remove someone (admins):** on their person card, "Remove from group". Everyone's phone gets a new key and a new code. The
  invite QR changes; old invites stop working. The chat shows "Anna removed Marco". Marco's phone shows "You were
  removed from Family".
- **Away for a while:** a phone that comes back after more than a week sees "Rejoining Family…" and gets back in by
  itself, as soon as a phone that's in the group is in reach. If someone was removed while it was away, it needs a new
  invite like anyone else.

## How it works on the wire

### Keys

- **Door:** the v0.5 group key, scrypt of the code, with its mailbox. Through the door travel only introductions
  (every member's, and a newcomer's request to join), new keys, and messages from a phone that isn't in yet.
- **Epoch secret:** 32 random bytes, made by a member's phone. Everything v0.5 derived from the group key is now
  derived from the current epoch secret for members' messages and receipts: message key, receipt key, mailbox,
  signature context. Phones read with every epoch they hold plus the door, and write with the current epoch (the door
  only while they have none). Epoch secrets are kept in the Keychain (iPhone) or encrypted with an Android Keystore key.
- **Group id:** HMAC-SHA256(door key, `darkproof-group-id-v1`), first 16 bytes. It never changes, even when the code
  does; member keys, saved public keys and checked people belong to it.
- **Member keys:** per group, the v0.5 signing key (P-256) and an **encryption key** (P-256, key agreement, kept the
  same way as epoch secrets). Both public keys go in the introduction.

### Introductions and joining

- Introductions are sealed with the door's introduction key. Their 4th field is `0x02`, the 33-byte compressed
  signing key, then the 65-byte uncompressed encryption key.
- A phone that has the code but no epoch is **joining**: its introduction is its request to join. Members' phones
  send theirs too (when they start using the group, and when the last one is more than 3 days old), so every code
  holder knows the members' ids and public keys, never their messages.
- When a member's phone sees a valid introduction from someone who isn't in its current epoch, it waits a random
  0–3 s and, if no new key including them arrived meanwhile, makes a **rekey** that includes them.
- A joining phone writes its messages through the door, so "I need help" works before anyone lets it in. Those few
  messages can be read by anyone with the code, and the app says so while it is joining.
- This also merges groups that were split: phones that each started the same group on their own, or that were apart
  past a key change, add each other the same way, and the highest epoch wins.

### New key (rekey)

A rekey is a packet sealed with the door's **rekey key** (HKDF-SHA256 of the door key, info `darkproof-rekey-v1`) and
signed by its maker. Body: `sender` = maker's member id, `name`, `text` empty, 4th field = `0x04` (or `0x05` for a
removal) then:

| Bytes | Field |
|---|---|
| 8 | epoch number, big-endian |
| 8 | when it was made, ms, big-endian |
| 33 | the maker's signing key (the signature must check with it, and its hash must start with the sender id) |
| 1 + 8·n | admins: a count, then member ids (8 bytes each) |
| 8 | the member id whose request it answers, or the person a removal removes, or 8 zero bytes |
| 2 + n·(8 + 2 + k) | parts: a count, then for each member: member id, length, HPKE box of the epoch secret (32 bytes), followed in a removal by the new code in UTF-8 |

- HPKE `info` = `darkproof-rekey-v1` ‖ the id of the door it travels through (16 bytes); `aad` = packet id (8 bytes) ‖
  member id (8 bytes). A phone that joined with a newer code derives a different id from it, so the door's id, not the
  group's saved id, is what both sides share.
- The members of the new epoch are the ids in its parts.
- A phone that is already in checks a rekey against the epoch before it (the one numbered one lower, or the current one
  if it doesn't hold that). Only that epoch's admins may leave members out or remove someone. The admin list only
  changes if an admin made the rekey; anyone else's rekey keeps the list that was there, whatever it claims. A removal
  also needs the phone to hold the epoch before it, so a higher number can't put it ahead of another removal; when the
  missing rekeys arrive, the phone reads its store again and the removal is accepted then.
- Anyone with the code may add people (a rekey that keeps every current member): everyone sees it, and this is also
  how split groups merge.
- A rekey numbered below the current epoch is kept to read old messages with and changes nothing.
- A joining phone accepts the first one that includes it: it has nothing better to trust than the code.
- A phone leaves a part out only by being removed: if a member's encryption key hasn't arrived, the rekey isn't made.
- A rekey is about 120 bytes per member; 100 members fit in one packet.

### The weekly key, and coming back

- A phone makes a new key, with the same members, when the current one is a week old plus a random delay of up to 6
  hours, so the group's phones don't all do it at once. The first one settles it for the rest. Phones check when they
  start and every hour while running. Any member can do it; the admin list stays as it was.
- Past the 6 hours, a phone has either missed the group's new keys or the whole group was quiet. It makes the new key at
  once, and shows "Rejoining…" until a new key or a message from someone else arrives.
- That new key is also the request to come back; there is no separate packet. Normally a returning phone just gets the
  latest key from the mesh. If those packets are gone, a member who sees a key made after its own current one but
  numbered below it knows that phone is behind, waits a random 0–3 s, and, unless another member did, makes a new key
  sealed to everyone. It won't if it made a key in the last hour, so a flood costs at most one key per phone per hour.
- If the whole group was quiet, each phone makes its own key with the same number when it returns, and they settle on
  one by the usual rule.

### Making the first epoch

- Creating a group makes epoch 1 at once, with the creator as its only member and admin.
- Groups saved before v0.6 count as created on each phone: every phone makes its own epoch 1, and the phones merge
  as above when they meet.
- Joining with a code makes nothing: the phone waits for a rekey.

### Two new keys at the same time

There is no server to put events in order, so two phones can make different rekeys for the same epoch (two people
removing someone at the same moment, or a weekly rekey crossing a removal). Rule:

- Every phone keeps **every epoch secret it was given, until 7 days after a newer one replaced it**, so it can read
  messages written under any of them, even one written on the key's last day.
- For writing, the winner of an epoch is a **removal** over anything else (or the removed person would still be in),
  then the removal by the **most senior admin** (the one listed first in the epoch before; the group's creator is
  first), then the rekey with the **smallest hash**. All phones reach the same choice without talking to each other.
  Seniority comes before the hash because whoever makes a rekey chooses its secret, and so its hash: a removed admin
  could otherwise publish a rival removal and pick the winner.
- A removal that lost doesn't count: no chat line, and the person it named isn't silenced or told they were removed.
  If a phone was told that first, a removal that outranks it and keeps that phone brings it back.
- If the two rekeys removed different people or added different admins, all of it holds, unless one maker was removed
  by a more senior admin's removal. Anyone still in the winning epoch who should be out is removed at once by the next
  admin's phone that sees it, and an admin's next rekey keeps every admin either one added.

### Removing and the code

The removed person still knows the old code, so a removal also makes a new code, sent to the remaining members inside
the rekey. Phones then follow only the new door, and the saved group, its invite and its messages move to the new code.

- A removal travels through the door the group had until then, so phones that were away can still open it.
- Through an old door a phone reads only a rival removal: one numbered the same as the removal it followed, from that
  same door, by an admin of the epoch before. Old doors are kept as long as their epoch, a week.
- A join request through the old door is ignored. A phone still joining with that code sees the removal go by, and
  the app tells it to ask for a new invite, if its invite names the admin who made the removal. With a typed code it
  can't tell that removal from one signed by anyone who has the code, so it goes on asking.
- Anything numbered above a removal that came through the old door is dropped when the removal arrives: it was made
  by someone who hadn't heard, or by the person removed.
- Messages and receipts from a removed member aren't shown, unless the phone had accepted them before the removal
  reached it and they are dated before it. The date alone can't decide: the sender writes it (FORMAT.md, "Removals and
  the code").
- The removed phone sees "You were removed", keeps what it has, and stops writing to the group or introducing itself.

### Forward secrecy, honestly

- Phones **delete an epoch secret 7 days after a newer one replaced it**, from the Keychain or Keystore-encrypted store
  too. Phones stop passing packets on after 7 days anyway, so nothing still travelling is lost. The messages on the
  phone go with the key, so a group's history lasts one to two weeks (decided 2026-11-08; the chat says so).
- This limits what is left **on the phone**. For traffic someone recorded, what counts is each member's encryption key:
  each new epoch secret is sealed to it. Phones replace that key every 7 days and delete a replaced one 14 days later
  (FORMAT.md, "Sealing for one member"), so whoever later gets the keys on a phone can open recorded rekeys only from about
  the last three weeks, not from the group's whole life. ML-KEM-768 is added to the seal, so a future quantum computer
  isn't enough either, except for rekeys made by or sealed to an iPhone before iOS 26.
- Member keys made in a Secure Enclave, or on Android 12 or later, can't be copied off the phone. Whoever holds the
  phone itself can still use them, and keeps receiving new keys like a member until that phone is removed. Keys made
  earlier, and those on older Android phones, are encrypted on the phone instead and could be copied by someone who breaks
  into it. Weekly keys alone don't lock out a stolen phone; removing it does.
- Epoch secrets can't be held the same way: the app has to read messages in the background while the phone is locked,
  so they are readable once the phone has been unlocked after starting.
- Each group message also has its own key, deleted once it has been checked (FORMAT.md, "Message keys"). A tree instead of
  Signal's chain lets keys be used in any order, because messages arrive late and out of order. Like Signal's sender keys, this
  protects the past and doesn't heal: someone holding a phone's keys can follow that epoch until the next new key.

## Limits and risks

- **Admins hold the power to remove.** A hostile admin could remove everyone; the chat shows who removed whom.
- **The first admin outranks the rest.** A newer admin who removes the group's creator can be overruled for a week,
  while the creator still holds the old door: the creator's rival removal wins. A removed admin who is listed after
  the person who removed them can't come back this way.
- **A member can split the group for a while** by making two keys in the same hour and sending each to different
  phones: each phone refuses the second one it sees. It lasts until the next new key, a week at most, and takes a
  member acting in bad faith.
- **Phones that each founded the same group** keep their own admin lists after they merge. This only affects groups
  saved before v0.6, on phones that never had a public release.
- **Spam:** a phone accepts at most one rekey per member per hour, except from admins (so one can remove two people in a
  row) and rekeys that let someone new in. The hour is measured on the rekeys' own dates, so it holds when the store is
  read again; a dishonest date can only space them out, at most 168 a week. A member's phone stops answering a join once
  that person is in.
- **Nonsense values:** a rekey numbered below 1, more than 1000 ahead of the current epoch, or dated more than 10 minutes
  ahead is refused.
- **Big groups:** with ML-KEM a rekey needs about 1.2 KB per member, so it goes in 1, 3 or 10 packets, and groups stop at 100 members. The 101st phone stays on
  "Asking to join".
- **Who is away when someone is removed** can follow the removal only while its packets last, a week. After that it
  needs a new invite.
- **Everyone (the Public channel)** stays as it is: anyone can read it by design.
- **LoRa-only phones** can't join or get new keys over the radio. Once they're in, messages still work over LoRa.
- **Clocks:** epochs carry the maker's time, used only to decide when a week is up. A phone with a wrong clock can
  start a rekey early or late; that wastes a packet, nothing more.
- **Review:** the design combines standard parts (HPKE, ECDSA, HKDF, AES-GCM), but the way they fit together is ours.
  It should get an outside cryptography review before GoDark describes it as secure.

## Why not MLS

MLS (RFC 9420) is the standard for group keys, used by large messengers. It needs every change to the group to be
put in one order by a server-like "delivery service". A mesh with no server, where phones are apart for days, can't
give that order, and the open-source libraries are in Rust and large. The design above keeps MLS's main ideas (a
random group secret, sealed to each member, replaced on removal) and gives up its per-change ordering in exchange for
the "smallest hash wins" rule.

## Moving from v0.5

There's no public release, so v0.6 can again be **new version only**: groups keep their codes, and the first v0.6
phone in each group makes epoch 1, and the others join it with the code as they update. Old v0.5 phones can't read v0.6 messages.

## Building it, step by step

Each step tested on both apps, simulator and emulator, before the next:

1. HPKE on both apps, checked against the RFC 9180 test vectors for this suite; encryption keys in the Keychain and
   Keystore; the spec text.
2. Epoch secrets: deriving every key from the epoch, keeping several epochs, deleting them after 7 days.
3. Join requests and the rekey that answers them, with the member list; "Asking to join…" and "Marco joined".
4. Done: "Remove from group", "Make admin", new code and invite, the admin rules above.
5. Done: weekly keys, rejoining after a long absence, limits (one rekey per member per hour, 100 members).
6. Done: both of two rival removals count; fault tests: two removals at once, a phone away for 10 days, a removed phone trying old and new doors, packets
   arriving out of order.

## Decided (2026-11-06)

1. **Way in:** anyone with the code joins; everyone sees it. No approval screens (Signal's group-link default).
2. **Removing:** admins only. The creator is the first admin and can make others admins (Signal's model).
3. **New keys:** on every join and removal, and at least every 7 days.
4. **Newcomers** see nothing from before they joined (follows from 3, as in Signal).
5. **History** lasts one to two weeks on each phone, and users are told (decided 2026-11-08).
