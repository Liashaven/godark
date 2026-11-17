# GoDark wire format (v0.6, marker byte 0xB3)

The Android and iPhone apps must produce and accept exactly these bytes.
`test-vectors.txt` holds byte-exact examples; both apps' unit tests check against it.
The app was called Blackout before. Protocol constants such as `blackout-mesh-v1`, `blackout-public`, `blackout-mesh` and `it.blackout.mesh.v1` keep that name on purpose: changing them would break every existing group and device.

## Packet

All integers are big-endian.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | marker | `0xB3`. Anything else is dropped (`0xB2` is v0.4). |
| 1 | 8 | id | Random. Written as 16 lowercase hex chars wherever it is used as text. |
| 9 | 8 | ts | Sender's clock, milliseconds since 1970-01-01 UTC, signed 64-bit. |
| 17 | 1 | ttl | Hops left, 0–64. Packets with ttl > 64 are dropped. |
| 18 | n | cipher | 1–16000 bytes. See below. |

Relays read only id, ts and ttl.

## Encryption

- **Key:** the group's **door** key; messages between members use a random epoch secret instead (see "Doors and
  epochs"). The door key is scrypt (RFC 7914) with N = 32768, r = 8, p = 1, 32-byte output. It needs 32 MiB of memory, so every guess
  of a code costs an attacker that memory and real time, not just a little CPU (on a 2024 laptop, about 60 ms).
  - Password: the group code, NFC-normalized, as UTF-8 bytes.
  - Salt: the ASCII bytes of `darkproof-group-v2`. It is the same for every group: the code must stay something people
    can read out or type, with nothing else to copy. Generated codes have 80 bits, far beyond guessing; apps warn
    that custom codes, especially short ones, can still be guessed.
  - Apps derive each key once and keep it in memory; only one derivation runs at a time.
- **Cipher:** AES-256-GCM with a 12-byte random IV and a 16-byte tag.
  - Associated data: the UTF-8 bytes of `<id hex>|<ts decimal>`, for example `0123456789abcdef|1793807238631`.
  - `cipher` = IV (12) ‖ ciphertext ‖ tag (16).
- **Plaintext:** the 64-byte signature (see "Signatures"), then three text fields in this order, then optional
  fields. Everything after the signature is the **body**.
  1. `sender`: the sender's member id in this group (see "Member ids").
  2. `name`: the display name.
  3. `text`: the message.
  4. Optional: a photo (see "Photos") or, in introductions, a public key.
- **Text field:** a 2-byte length followed by that many bytes of standard UTF-8. Do not use Java's modified UTF-8.
- Readers ignore bytes after the fields they know, which leaves room for future fields.

A packet that fails to decrypt is still stored and forwarded. It just isn't shown.

### Padding

Zero bytes after the last field make every whole packet (header included) one of these sizes: **163, 233, 512, 1024, 2048,
4096, 8192 or 16018 bytes**, the smallest that fits. 163 and 233 are the MeshCore and Meshtastic limits, so a packet that fit
a radio before still does. The padding is part of the body, so it is encrypted and signed; it reads as an empty 4th field
or is ignored. New keys are always padded to 16018, whatever their real length, because it would count the group's members.
Anyone watching still sees how many packets there are.

### Times

So that someone who stores packets can't read when each was written, `ts` in the clear header is blurred. With W = 2^20 ms
(about 17 minutes) and mask = the first 3 bytes of HMAC-SHA256(key, the ASCII bytes of `darkproof-time-v1` ‖ the 12-byte IV)
as a big-endian number, low 20 bits only:

    header ts = floor(ts / W) * W - W + ((ts mod W) XOR mask)

The header is therefore up to 35 minutes before the real time and never after it, so forwarding rules still work. Readers undo
it with the key; associated data, the signature and the time shown all use the real `ts`. A packet that wasn't blurred (the
test vectors) opens too. A relay still sees when a packet reaches it.

## Member ids

Each phone has a separate key in each group (the Public channel counts as one), so nobody can tell that two groups
have the same person in them, or match a person to a phone they see over Bluetooth or Wi-Fi.

- **Member key:** a P-256 (secp256r1) key pair, made at random the first time the phone uses the group and kept in the
  phone's secure storage (Android Keystore, iPhone Keychain). The private key never leaves the phone. Reinstalling the
  app or resetting the phone makes new member keys, which the others see as a new key (see "Person emoji").
- **Public key:** the 33-byte compressed point (SEC 1: `02` or `03`, then x).
- **Member id:** the first 8 bytes of SHA-256(public key) as 16 lowercase hex chars. It goes in the `sender` field
  of the member's messages, receipts and introductions in that group.
- Posts from the Wi-Fi board (Android) carry `web-` and the host phone's Public member id, and are signed with the
  host phone's Public member key: readers know they came through that phone, not who typed them. For forwarding they
  are other people's packets, not the host phone's own: on the relays they wait their turn with the packets it passes
  on, and together they count as one link's share of the packets it keeps for passing on (see "A full queue"). The
  board takes at most 10 posts a minute in all, fewer than the 13 packets a minute a phone passes on to the relays,
  and at most 4 of them from one visitor's address, so one visitor can't use up everyone's.
- Vectors: `kind: member` (public key → member id and emoji).

## Signatures

Every packet a phone writes (messages, receipts and introductions) is signed with the writer's member key in that
group, inside the encryption, so nobody else in the group can write under another member's id.

- **Signature:** ECDSA over P-256 with SHA-256, as r ‖ s (32 bytes each, big-endian), the first 64 bytes of the
  plaintext. ECDSA signatures differ every time; only checking them is reproducible.
- **Signed message:** the ASCII bytes of `darkproof-sig-v1`, then the **context** (32 bytes), the packet id (8 bytes),
  `ts` (8 bytes, big-endian) and the body. Context = HMAC-SHA256(the key the packet is sealed with, the ASCII bytes of
  `darkproof-sig-context-v1`). A signed body can't be moved to another group, kind of packet, id or time.
  A packet sealed with a message key signs a different message, with the epoch's outer key for the context (see
  "Message keys").
- **Checking:** the reader takes the public key of the `sender` member id (`web-` removed) from that group's
  introductions or the keys it saved, then:
  - the signature checks → the message is that member's;
  - it doesn't → the packet is dropped like one it can't open: stored and passed on, never shown;
  - no public key known yet → shown with "not verified yet", and checked again when the introduction arrives.
- **The sender field:** a message or receipt whose `sender` is not a member id (16 lowercase hex chars), or `web-` and
  one, is dropped like a packet the reader can't open: no key could ever be known for it. Each app marks the user's own
  messages with an id of its own that is never sent; a received `sender` equal to that id is dropped the same way,
  whatever its shape. Only the phone's own member id is shown as its own, and that packet's signature is then checked
  with the phone's own key. So nothing received can pass for written on this phone.
- **Waiting for a key:** what a phone keeps to check later, for a message shown as "not verified yet" or for a receipt:
  - It belongs to one packet, not to an id. Several packets can carry one id (see "The same message again"). When
    an introduction arrives, a waiting check marks or removes a message only if it was kept for the very packet that
    message is shown from; a packet that got no row in the chat doesn't wait at all. Packets are told apart
    by their id together with SHA-256 of the signed digest and the signature.
  - `web-` in front of the sender doesn't count: a Wi-Fi board post waits for its host phone's introduction.
  - Each group and the Public channel have room of their own, 1,000 packets each. When a channel's room is full its
    oldest goes, and what waited for a message goes when that message leaves the phone. Public channel packets, which
    anyone can write under ids that are never introduced, therefore can't keep a group's messages from being checked.
  - A message that no longer waits stays "not verified yet" until the phone next reads its store (when the app
    starts, at the latest), which checks every stored packet again.
- Phones save the public keys they learn, per group (at most 500 per group, the most recently seen), so messages stay
  checked after the introductions expire. Of people who aren't in the group they keep at most 20 (see "Joining"). An
  introduction that brings nothing new, such as one read again from the store, is not saved again.
- Size: a signature adds 64 bytes. Over MeshCore (163 bytes) a check-in still fits with a short name and no position.

## Introductions

A member's public key travels in an introduction, an ordinary packet in the group's mailbox sealed with the group's
**introduction key**: HKDF-SHA256 with the group key as input key material, no salt, info = the ASCII bytes of
`darkproof-intro-v1`, 32-byte output. Apps that can't open it relay it like any other packet.

- Sealed with the door's introduction key, whatever the epoch.
- Body: `sender` = the member id, `name` = the display name (empty on the Public channel: nothing reads it there, and
  a post carries its sender's name itself), `text` = empty, 4th field = the byte `0x03`, the 33-byte
  compressed signing key, the 65-byte uncompressed encryption key and the 1184-byte ML-KEM-768 key (see "Sealing for one
  member"). The Public channel uses the byte `0x02` and leaves out the ML-KEM key; in a group that is refused. Signed like
  every packet, with the signing key.
- Valid only if SHA-256(signing key) starts with the member id, the encryption key is a valid P-256 point, and the
  signature checks with the signing key.
- A member's encryption keys are replaced only by an introduction with a later `ts`, so an old one played back can't
  bring back a key they have deleted.
- An introduction from someone who isn't in the current epoch is that phone's request to join (see "Joining").
- A phone sends its introduction to a group when it first uses it, then whenever its last
  one there is more than 3 days old: at app start and before it writes. So a member's introduction is always among
  the packets of the last 7 days that new phones receive. To the Public channel it sends one, under the same 3-day
  rule, only before its user writes there (or someone posts through its Wi-Fi board), and at app start only while its
  newest post there is less than 7 days old, so readers can still check that post. A phone whose user never posts on
  the Public channel never announces itself there.
- Vectors: `kind: signed` (a signed message and its introduction, with fixed IVs and a fixed signature). The
  `signed-intro` vector checks sealing and signing; its 4th field is the older 34-byte shape, without the encryption key.

## Sealing for one member (HPKE)

Used to give a new epoch secret to one member only (see "New keys").

- HPKE (RFC 9180), base mode, single shot: KEM DHKEM(P-256, HKDF-SHA256) (`0x0010`), KDF HKDF-SHA256 (`0x0001`),
  AEAD AES-256-GCM (`0x0002`), sequence number 0.
- Sealed box: `enc` (the 65-byte uncompressed ephemeral public key) ‖ ciphertext ‖ 16-byte tag.
- The recipient's key is its member **encryption key**, a P-256 key-agreement key kept apart from the signing key.
  Where the phone allows it (Secure Enclave, Android 12 or later), new member keys are made inside secure hardware and
  the private key never leaves it. Nothing on the wire changes.
- Both apps implement it from their platform's primitives (CryptoKit's own HPKE needs iOS 17); the iPhone tests check
  it against CryptoKit's HPKE in both directions. Vectors: `kind: hpke` (a fixed ephemeral key).
- **Post-quantum:** when the recipient has an ML-KEM-768 key (FIPS 203), the box is the 1088-byte ML-KEM ciphertext,
  then HPKE in PSK mode (`mode_psk`) with the ML-KEM shared secret as the PSK and `darkproof-mlkem768-v1` as its id. Opening
  it needs both the P-256 key and the ML-KEM key. Android uses BouncyCastle, iPhones CryptoKit, so the iPhone app needs iOS 26
  or later. A box without ML-KEM is refused, and a new key isn't made until every member's ML-KEM key is known. Vectors:
  `kind: mlkem`, `kind: hpke-psk`.
- **Changing keys:** a phone makes a new encryption key and ML-KEM key for a group when its current one is 7 days old, and
  introduces itself at once. It keeps a replaced key for 14 days, so new keys sealed to it can still be opened, then
  deletes it. Someone who later takes the phone can open recorded new keys only from about the last three weeks.
  A phone that was removed from the group keeps to this schedule (checked every hour), so its keys go on time too;
  it only stops introducing itself, and its new keys are never sent.

## Doors and epochs

The group code doesn't read messages. It opens the group's **door**, and messages are sealed with a random **epoch
secret** that changes. spec/DESIGN-v0.6-groups.md has the reasoning; this section is the rule.

- **Door:** the 32-byte key scrypt makes from the code (see "Encryption"). Only introductions and new keys travel through
  the door. In a group nothing else is read through it, so the code alone doesn't let anyone write.
- **Epoch secret:** 32 random bytes, made by a member's phone and sealed to each member. A phone keeps only what it derives,
  then forgets the secret: the **outer key** (HKDF-SHA256 of the secret, no salt, info = the ASCII bytes of
  `darkproof-epoch-outer-v1`, 32 bytes), which takes the place of "the group key" everywhere in this document (receipt key,
  mailbox, signature context, headers), and each sender's message keys (see "Message keys").
- **Reading and writing:** a phone reads with every epoch it holds and writes with the current epoch. A phone with no epoch
  can't write; what it tries to send waits until it is let in.
- **Only members write in an epoch:** a message or receipt sealed with an epoch's keys is read only if its `sender` (a
  `web-` in front doesn't count) is in the member list that came with that epoch. For a message sealed with a message
  key this is the rule "Whose number"; for one sealed with the outer key, and for a receipt, the phone looks the
  sender up in the list. Every member holds the outer key, and so does someone removed since: without this, a packet
  under an id nobody was let in with, or under a key someone only introduced through the door, would be shown (as
  "not verified yet", or as checked) with any name. An epoch kept only to read with (see "Accepting a new key")
  decides nothing with its list but still reads by it, and that list is whatever its maker wrote. So the sender also
  has to be in the member list of an epoch the phone holds that isn't kept only to read with. Anything else is dropped
  like a packet whose signature doesn't check: stored and passed on, never shown.
- **Current epoch:** the highest number. For the same number: a removal beats anything else; then the removal whose
  maker comes first in the admin list of the epoch before; then a key made by an admin of the epoch before, ahead of
  one made by a member who isn't (a member picks their key's secret, and so its hash); then the smallest SHA-256 of
  the secret. Two keys with the same secret, number and standing: the smallest maker id, then the smallest new code.
  "The epoch before" is as in "Accepting a new key"; a phone still joining goes by the admin list of the key that
  lets it in.
- **One secret, several keys:** an epoch is its secret together with its number, its maker and, for a removal, the new
  code and the person removed. A new key that carries a secret the phone already holds under another of these is a
  separate epoch, judged by the same rules as any other; only the same key read again is ignored. Whoever was given a
  secret can send it on in a key of their own, so the first key to bring a secret must not keep out the others.
- **Keeping:** a phone holds at most 64 epochs. Over that, one kept only to read with (see "Accepting a new key") goes first, the last of them in the order of "Current epoch"; if there is none, the lowest epoch. Of those kept only to read with, a phone holds at most 4 from one maker, dropping the last of that maker's in the same order: a member can make as many as the hourly limits allow, and they must not push out the epochs before the current one. An epoch is deleted 7 days after a newer one replaced it, and with it every epoch of the same number that lost to it. The current one stays, however old. Stored
  packets that nothing can open any more and that are older than 7 days are deleted too, so a group's messages last one
  to two weeks on a phone. A newer epoch replaced it at that epoch's date or when this phone got it, whichever is
  later: the date is whatever its maker wrote, and one long past must not delete the epoch before it at once. A phone
  that was away therefore keeps an epoch up to 7 days after it came back.
- **Door id:** HMAC-SHA256(door key, the ASCII bytes of `darkproof-group-id-v1`), first 16 bytes. A phone keeps the id
  of the first code it had for its member keys and saved public keys, even after the group's code changes.

### New keys

A new key is a packet sealed with the door's **rekey key** (HKDF-SHA256 of the door key, no salt, info = the ASCII bytes
of `darkproof-rekey-v1`, 32-byte output) and signed by its maker. Body: `sender` = the maker's member id, `name`, `text`
empty, 4th field:

| Bytes | Field |
|---|---|
| 1 | `0x06`, or `0x07` for a removal |
| 8 | epoch number, big-endian |
| 8 | when it was made, ms, big-endian |
| 33 | the maker's compressed signing key; the signature must check with it, and its hash must start with `sender` |
| 1 + 8·n | admins: a count, then member ids, most senior first |
| 8 | the member id whose join it answers, or the person a removal removes, else 8 zero bytes |
| 2 + 8·m | members: a count, then everyone in the new epoch |
| 2 + n·(8 + 2 + k) | parts: a count, then for some members: member id, length, box |

- **Several packets:** a new key goes in 1, 3 or 10 packets for at most 10, 30 or 100 members, parts spread evenly, each
  packet with its own id and the whole member list. A phone needs only the packet with its part and ignores the others.
  With k packets, packet i (from 0) holds the parts of the members at places i, i + k, i + 2k, … of the member list, in
  that order.
- A packet whose parts aren't exactly those of one such packet is refused by every phone: a part for someone not in the
  member list, a part missing, or parts out of order. Up to 10 members that means a part for each of them, so a maker
  can't list someone and give them none.
- A packet that lists more than 100 admins or more than 100 members, or carries more than 10 parts, isn't read at all:
  the lists are read before the signature can be checked, and anyone with the code can seal such a packet.
- A box holds the 32-byte epoch secret, followed in a removal by the group's new code in UTF-8, which has to be in the
  generated form (see "Typed codes"). Any other shape is refused.
- HPKE `info` = the ASCII bytes of `darkproof-rekey-v1` ‖ the id of the door it travels through (16 bytes). `aad` =
  packet id (8 bytes) ‖ member id (8 bytes).
- A new epoch is the current number + 1. If any member's encryption key is missing, the phone doesn't make it.

### Accepting a new key

The signature is checked first. Then, with "the epoch before" meaning the held epoch numbered one lower, or the current
epoch if there is none:

- **Refused outright:** a number below 1 or above 2^53, more than 1000 above the current epoch, a date below 0 or more
  than 10 minutes ahead, or more than 100 members.
- **A phone with no epoch** accepts the first one that includes it. If the invite it joined with names admins, the
  maker has to be one of them; if not, the first key it sees has to be trusted (see "Invites"). A removal that doesn't
  include it means its code no longer works, if the invite names admins and the removal's maker is one of them: from
  then on the phone accepts no new key through that code, and it remembers this when it restarts. Otherwise the person
  removed, whom an invite made earlier still names, could let it into a group of their own. With a typed code, or a
  link that names nobody, such a removal is ignored: anyone who has the code can sign one, and it must not be able to
  shut the phone out of the group it is joining.
- **Someone a removal took out** decides nothing afterwards and adds nothing, if that removal won its number. A new
  key of theirs that isn't a removal is refused, whatever its number and whichever door it comes through. The epoch
  before the removal lists them for another week, and a key numbered below the removal, through the old door, would
  otherwise be kept to read with: its secret and date are theirs to choose, so it could outlive the removal, and then
  nothing on the phone says that its maker was removed. A removal of theirs is refused when it is numbered one above
  that removal, and also, through the current door, when it is numbered below it: they may have learnt the new code.
  Numbered below it through the old door, seniority decides (see "Through an old door"). The cost: a key they made
  before they were removed, which reaches a phone only after the removal, isn't taken there, so that phone can't read
  what others wrote with it.
- **Only admins of the epoch before** may let someone in, leave a member out or make a removal. Anyone else's new key has
  exactly the same members as the epoch before, and its maker has to be one of them. A removal needs the epoch before it to
  be held. A removal may not include the person it removes.
- **Several epochs before:** when a phone holds rivals with that number, the first of them (see "Current epoch") gives the
  members, and an admin of any of them counts as an admin, with their best place as their seniority. A rival that lost
  doesn't count once a removal that won its number, the same or a higher one, took its maker out: through an old door
  that person can still send one.
- **The admin list** changes only if an admin of the epoch before made the new key. Otherwise it stays as it was,
  whatever the packet says.
- **At most one per member per hour**, compared by the dates of the keys held, and at most 4 per member in the last hour
  as they arrive on this phone, since a key's date is whatever its maker wrote. Neither applies to admins.
- **Numbered below the current epoch:** kept only to read with, and only from someone who is a member of an epoch this
  phone holds. Unless it is a removal, its member list isn't kept; unless an admin made it, its admins are those of the
  epoch before. Such an epoch decides nothing, neither who is an admin nor how senior they are: "the epoch before" a later
  key is one with a member list, else the current epoch. It isn't taken at all once it is past its week (see
  "Keeping"): a newer epoch replaced it more than 7 days ago, counted like there with its date.
- **Through an old door** (a code the group has moved on from): only a removal with the same number as the removal this
  phone followed out of that door, or a new key numbered below that removal. A removal numbered below it is accepted
  only if its maker comes before the maker of every removal the phone holds with a higher number, in the admin list
  of the epoch before it. It then wins like a rival that beat the removal followed (see "Removals and the code").
  Otherwise an admin who is being removed could send a key and then a removal of their own one number higher, and
  phones that got those first would never take the removal. Without the seniority, someone removed could pick a lower
  number and undo their own removal.
- **A part that doesn't open:** a new key that isn't a removal, through the current door, that lists this phone and
  passes the rules above, but whose part for this phone doesn't open or isn't 32 bytes, when the others may be writing
  with it: it is numbered above the current epoch, or the same and wouldn't lose to it whatever the hashes. The other
  phones can't see that. This phone waits a random 0–3 s and then, like a phone that was away (see "The weekly key, and
  coming back"), makes a new key of its own and shows that it is rejoining; an hour later it makes one more, because
  the first can have the same number as the key it couldn't open and lose to it. It makes neither once a key that
  settles it has arrived: a higher-numbered one, or one of the same number that beats the unopened key whatever the
  hashes. If it made a key in the last hour it waits for its hourly check.
- **Trying a part:** opening a part is a key agreement in the phone's secure hardware. Once 4 parts from one maker
  haven't opened in the last hour, by the phone's clock, it tries no more of that maker's for that hour and treats
  them as parts that don't open. A phone with no epoch can't tell who is in the group: it stops at 16 from all makers
  together.
- Phones read their stored packets again after each new epoch, so a new key refused because an earlier one hadn't
  arrived is accepted when it does. A part is opened once: a phone remembers the parts it has opened (the last 512,
  each named by SHA-256 of the part and of the key's maker, number, date and kind) and keeps that list across
  restarts, saved after the epochs. So a stored new key read again costs no key agreement, and never brings back an
  epoch the phone has deleted.

### Removals and the code

- A removal carries the group's new code in each box. It travels through the door the group had until then. A phone
  ignores a removal whose new code is the code of another group it has saved: followed, it would put this group in
  that group's place on the phone.
- A phone follows a removal's code if it's the newest removal, or a late one that beat the removal it had followed:
  a rival with the same number, or a more senior admin's removal with a lower number (see "Through an old door").
  Epochs numbered above it are then dropped. Door id, member keys and saved messages stay; the invite changes.
- Old doors are kept as long as the epoch that came through them, for rival removals only. Introductions and messages
  through an old door are ignored.
- A code the group has moved on from isn't a second group. On a phone that has the group saved under its new code,
  joining with the old code (an old invite) or writing to it leads to that group, and the old code isn't saved: only
  one set of keys reads and writes a group's epochs.
- The removed phone stops writing to the group and introducing itself, and still deletes its replaced encryption keys
  on time ("Changing keys"). It can be told by mistake by a removal that
  loses; a more senior removal that includes it undoes that: one with the same number, or one with a lower number
  whose maker comes before the maker of the removal that removed it, in the admin list of the epoch before the lower
  one. A phone named by a removal that wins this way from a lower number is removed.
- **What the person removed wrote:** once a phone holds the winning removal, it shows nothing from that member that
  it sees for the first time, whatever date the packet carries. The date is the sender's to write, and the person
  removed still has the keys of the epochs before, which phones read with for another week: dated a minute before
  the removal, anything written in that week would otherwise be shown, confirmed and alerted like a member's. What
  the phone had accepted before stays, unless it is dated after the removal: that is a message it reads from its own
  copy (see "Message keys"), or a message or receipt that was waiting for its sender's public key. So after a
  restart, of that member, a phone shows the messages it has a copy of; their receipts, and messages sealed with the
  outer key, have no copy and no longer count. The cost: a message they really wrote before the removal, which reaches
  a phone only after the removal did, isn't shown there. A phone can't tell it from one written afterwards.
- **Two admins at once:** each removal numbered the same counts unless its maker was removed by a more senior one, or
  it lost and its maker is no longer an admin of the current epoch (a phone can't tell when a late one was made).
  People a counted removal took out who are still in the current epoch are removed by the next admin's phone that
  sees it, after a random 0–3 s unless another did. An admin's next new key also keeps admins added by a rival that
  didn't win.

### Joining

- A phone with the code and no epoch sends its introduction; that is its request.
- An admin's phone that sees a valid introduction, through the current door, from someone not in the current epoch shows
  the request, with that person's emoji. It isn't answered automatically: an admin chooses to let them in, which makes a
  new key that includes them, up to 100 members, or turns them down, which is remembered. While no admin is in reach,
  nobody can join.
- Anyone with the code can introduce as many made-up keys as they like. A phone therefore keeps the keys of at most 20
  people who aren't in the group and are asking: introduced in the last 7 days, not in the current epoch, not turned
  down on this phone. A key it doesn't know yet from someone who is in no member list it holds is not kept while those
  20 places are taken; a request that is waiting is never pushed out by a later one. An admin's phone shows at most
  those 20 and alerts at most once a minute per group.
- Creating a group makes epoch 1 at once, with the creator as its only member and admin. Groups saved before v0.6 count
  as created on each phone.

### The weekly key, and coming back

- A phone makes a new key with the same members when the current epoch is 7 days old plus a random delay of up to 6
  hours, checked at start and hourly. The 7 days count from the epoch's date or from when this phone got it, whichever
  is later, so a key dated in the past isn't due at once.
- Past the 6 hours it does so at once, and shows that it is rejoining until a new key or a message from someone else
  arrives. While it is, a removal it can't follow tells it that the group has a new code only if it came through the
  door the phone has for the group and its maker is an admin of the phone's current epoch whom no removal has taken
  out: anyone who has the code can sign a removal.
- A member who sees a new key made after its current epoch but numbered below it, from a member, through the current
  door, knows that phone is behind. It waits a random 0–3 s and, unless another did and it hasn't made a key in the last
  hour, makes a new key for everyone. A key dated more than 10 minutes ahead doesn't count, and one member's keys
  count once an hour by the phone's clock. "Another did" means the phone's current epoch is no longer the one it had
  when the key came, whatever that key's date: the date is its maker's to write.

## Message keys

Each group message has its own key, which a phone deletes once the message has been checked. Packets arrive late and out of order, so the keys are the leaves of a tree, usable in any order.

- **Trees:** per epoch, one per member. Root = HMAC-SHA256(epoch secret, the ASCII bytes of `darkproof-tree-v1` ‖ the 8-byte
  member id). Each node has two children, HMAC-SHA256(node, one byte 0 or 1), 16 levels deep, so 65,536 messages per
  sender and epoch. A phone derives the roots when it gets an epoch and forgets the secret.
- **Message key:** HMAC-SHA256(leaf, the ASCII bytes of `darkproof-message-v1`).
- **Packet:** `cipher` = IV (12) ‖ header (3, masked) ‖ AES-256-GCM ciphertext ‖ tag. The header is the sender's position in
  the epoch's member list (1 byte) and the message number (2 bytes), XORed with the first 3 bytes of HMAC-SHA256(outer key,
  the ASCII bytes of `darkproof-header-v1` ‖ IV). Associated data: `<id hex>|<ts decimal>` followed by the unmasked header.
  Plaintext as in "Encryption".
- **Signed message:** the ASCII bytes of `darkproof-sig-mk-v1`, then the context of the epoch's outer key (32 bytes, see
  "Signatures"), the packet id (8 bytes), `ts` (8 bytes, big-endian), the unmasked header (3 bytes: position, then number)
  and the body. Every member of an epoch can derive every member's message keys, and the associated data proves only
  that. With the position and number signed, a member can't take a message someone signed and seal it again under that
  person's unused numbers: the copy opens, but its signature no longer checks, so no key is deleted. The tag differs
  from `darkproof-sig-v1` so that a signature can't be moved between a packet sealed with a message key and one sealed
  with the outer key either.
- **Whose number:** a packet opens only if the position in its header is the sender's own place in the member list (a `web-`
  in front of the id doesn't count), so a member can't seal a packet under someone else's number and sign it as themselves.
- **Without a message key:** a sender whose numbers have run out seals with the outer key, as in "Encryption". Such a
  packet is read only from a member of that epoch (see "Only members write in an epoch").
- **Deleting:** a leaf is deleted once the signature has checked, never before, so a member who forges a packet under someone
  else's number can't destroy that number's key. Deleting replaces the node above it with its other branches, so nothing kept
  can derive a deleted leaf. A sender deletes the leaf as soon as it has sealed the message.
- **The same message again:** a phone alerts and sends a receipt only for a message it wasn't showing yet. Messages
  are told apart by their packet id together with the first 8 bytes of the signed digest, without the signature: the
  same signed message sealed again, or carrying the other signature that checks for it, is the same message. A packet
  under an id that is taken (see "The same packet") that brings a message already shown, or that names this phone as
  its sender, is not kept and changes nothing on screen. Any other is a message of its own: it is kept and shown, and
  a receipt names it by its packet id. So whoever sends a message of their own first under someone's id doesn't keep
  the real one off the screen. This holds on the Public channel too.
- **This phone's copy:** the app can no longer re-read a message from its packet, so it keeps a copy sealed with a key that stays
  on the phone. The copy goes when the packet goes or when the epoch is deleted, so history lasts as long as before.
  When the epoch is deleted, the copies sealed under it, their packets (which no longer open) and their messages on
  screen go at once, not at the next read of the store. A copy can be up to about 1 KiB longer than the largest packet
  (it adds the group and epoch ids, lengths, nonce and tag); a phone's store of copies reads back copies up to 1 KiB
  over `maxCipher`, and a phone never seals a packet of its own over `maxCipher`.
- **Alerts:** an alert shows a message's text, so it must not outlive the message. When a phone deletes a message, its
  alert goes too (iPhone: alerts are posted under the message id; Android: while the app runs). An alert also goes
  by itself: on Android a week after the message's date (a minute at least), on iPhone a week after it was posted.
- **What this protects:** someone who records traffic and later takes a phone's keys can't open a message that phone has already
  handled, except through the copies on the phone, which last one to two weeks. A message the phone hasn't received yet can
  still be opened with those keys. As in Signal's groups, a thief who keeps the keys can follow later messages of that
  epoch until the next new key.
- Receipts, introductions and new keys don't use message keys. The Public channel doesn't either.
- Vectors: `kind: message-key` (`signed_message` is the signed message above for that packet).

## Person emoji

Sixteen emoji, shown eight to a line, that two people compare, each on their own phone, to check that a member's key is
really that person's.

- SHA-256 of the ASCII bytes of `darkproof-person-emoji-v1` followed by the public key; its first 12 bytes, read 6 bits
  at a time from the top, are 16 indices into the emoji list of "Group fingerprint".
- 96 bits: someone who wants a key with the same emoji has to make about 2^95 keys.
- When the emoji match, the user marks the person **checked**: the phone saves that public key for the person.
- **New key:** when someone writes under the same name as a checked person (the name key of "Reports about others")
  but with another member id, apps warn that this is a new key: either the person reinstalled GoDark or reset
  their phone, or someone else is using their name. A name that differs from a checked one only in characters that
  draw nothing, or in a compatibility form of its letters, has the same key and warns too. A checked person saved
  with an older form of the key is matched by making that key again.

## Link ids

The **node id** that phones exchange when they link (Bluetooth LE and Wi-Fi HELLO, the Bonjour instance name, the
Nearby endpoint name, the Multipeer peer name) is a **link id**: 12 random lowercase hex chars, new every time the app
starts, never saved and unrelated to member ids. Someone who sees phones over the air can follow one only until its
app restarts, and can't tell who it belongs to.

- After a restart a phone has a new link id, so other phones see a new neighbour; its old links close (a HELLO with a
  different node id means disconnect, and dead TCP links time out).

## Groups and the Public channel

- **Every GoDark device relays for every other.** Devices connect to any GoDark device they find, whatever its group, and forward all packets. A group exists only through its code: only members can decrypt its messages.
- **Public channel:** messages sealed with the code `blackout-public`, which everyone knows. Anyone can read and post them, including people without the app through the Wi-Fi board (Android). Apps show them marked as public.
- **Reading:** a device tries its own group's key first, then the public key, then the keys of the other groups saved
  on it (each derived once, in the background). A packet that opens with none is relayed but not shown. Messages of
  every saved group are kept, confirmed (with that group's receipt key) and alerted, not only the group on screen.

## Invites

An invite link carries a group's name and code so nobody has to type the code:

```
darkproof://join?name=<group name>&code=<group code>&admins=<pins>
```

- Both values are URL-encoded query items. `code` has at least 8 characters. `name` is only a label shown on screen; it is not used for encryption, and a missing name means "Group".
- Apps show the link as a QR code and can send it any way the phone can share a link, such as AirDrop.
- New groups get a random code of 16 characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, in four groups of four joined by `-` (80 bits of entropy).
- Anyone with the link can ask to join, exactly like anyone who knows the code.
- **`admins`** names who can let the joining phone in: for each of the group's first 5 admins whose key the inviting phone
  knows, the first 16 bytes of SHA-256 of their 33-byte public key, in lower-case hex, run together. A phone that joined with
  such a link ignores new keys from anyone else while it has no epoch, so someone who knows the code can't pose as the group.
  Once it has an epoch the usual rules apply. An `admins` item that isn't in this form counts as none.
- The admins are those of the invite the user chose to join with, kept when the phone first saves that code. Reading a
  link keeps nothing, and a link for a code the phone already has changes nothing, so a link opened later can't replace
  or push out the admins a pending join trusts.
- A typed code, or a link without `admins`, can't name anyone: that phone trusts the first new key that includes it.
- An admin appointed after the invite was made isn't named in it. A phone joining with that invite waits until a named
  admin lets it in or makes a new key.

### Legacy web invite links

Older invites may contain a URL such as `https://darkproof.app/join#name=<group name>&code=<group code>&admins=<pins>`.
This is a legacy input format only: GoDark does not control that domain, the current GoDark site does not host a join
page, and the app's sharing UI does not generate these web URLs. The app continues to parse an old link if a user pastes
or shares one into GoDark; the code remains in the URL fragment and is not sent to a web server by a normal browser.

- After `#` come the same encoded items as in the `darkproof://` link. Every byte that is not a letter, digit, `-`,
  `.`, `_` or `~` is written `%XX` (so a space is `%20` and `+` is `%2B`); see `kind: invite` in `test-vectors.txt`.
- The legacy parser accepts `http://`, `www.darkproof.app`, case variations, `/join/` and `/join.html`, and a query
  before the fragment. A code in the query instead of the fragment is not an invite.
- When `name` or `code` appears twice, the first one counts.
- The app-generated `darkproof://join` URI is retained for compatibility with existing GoDark installations. Package,
  storage and wire identifiers are not changed in this release.

### Typed codes

When someone types or pastes a group code to join, apps clean it up first, so a code read aloud or copied by hand still
reaches the same group:

1. If the input (trimmed) is an invite link of either form, its code is used exactly as the link carries it.
2. Otherwise apps remove spaces, tabs, line breaks, `-`, `_`, the no-break space and the dashes U+2010–U+2015 and
   U+2212, and turn ASCII `a`–`z` into upper case. If that leaves exactly 16 characters, all from the generated-code
   alphabet `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, the code is those 16 in four groups of four joined by `-`, for example
   `k7qf 2m9x pa4t w8rj` → `K7QF-2M9X-PA4T-W8RJ`.
3. Anything else is a custom code: only leading and trailing white space is removed, and everything else is kept as
   typed (case, spaces, dashes).

- Only new input is cleaned. Saved groups keep the code they were created with, because a custom code that happens to
  look like a generated one would otherwise change group.
- A code is in the generated form when it matches `^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$` (80 bits). Apps refuse to
  join with anything else: everyone can download a group's packets from the relays and try guesses on them at leisure,
  with one salt for all groups. A group saved earlier under another code keeps working.
- Vectors: `kind: code-normalize`.

## Group fingerprint

Five emoji that two people read out to each other to check that their phones are in the same group. A fake invite QR
code, or a code typed with a mistake, gives different emoji.

- Take HMAC-SHA256 with the group key (see "Encryption") as the key and the ASCII bytes of `darkproof-fingerprint-v1`
  as the message. Read its first 4 bytes as a big-endian 32-bit number; its 30 highest bits, 6 bits at a time from the
  top, are five indices from 0 to 63.
- Index → emoji and English name, from Matrix's SAS emoji list (matrix-org/matrix-spec,
  `data-definitions/sas-emoji.json`, Apache License 2.0), in its order: 🐶 Dog, 🐱 Cat, 🦁 Lion, 🐎 Horse, 🦄 Unicorn,
  🐷 Pig, 🐘 Elephant, 🐰 Rabbit, 🐼 Panda, 🐓 Rooster, 🐧 Penguin, 🐢 Turtle, 🐟 Fish, 🐙 Octopus, 🦋 Butterfly,
  🌷 Flower, 🌳 Tree, 🌵 Cactus, 🍄 Mushroom, 🌏 Globe, 🌙 Moon, ☁️ Cloud, 🔥 Fire, 🍌 Banana, 🍎 Apple, 🍓 Strawberry,
  🌽 Corn, 🍕 Pizza, 🎂 Cake, ❤️ Heart, 😀 Smiley, 🤖 Robot, 🎩 Hat, 👓 Glasses, 🔧 Spanner, 🎅 Santa, 👍 Thumbs Up,
  ☂️ Umbrella, ⌛ Hourglass, ⏰ Clock, 🎁 Gift, 💡 Light Bulb, 📕 Book, ✏️ Pencil, 📎 Paperclip, ✂️ Scissors, 🔒 Lock,
  🔑 Key, 🔨 Hammer, ☎️ Telephone, 🏁 Flag, 🚂 Train, 🚲 Bicycle, ✈️ Aeroplane, 🚀 Rocket, 🏆 Trophy, ⚽ Ball, 🎸 Guitar,
  🎺 Trumpet, 🔔 Bell, ⚓ Anchor, 🎧 Headphones, 📁 Folder, 📌 Pin. The exact code points (some with U+FE0F) are in
  `kind: fingerprint-list`.
- Apps show the emoji separated by spaces and the names separated by `, `.
- Test values: `test-group-1` → HMAC `7a23a477f07a388a…`, indices 30 34 14 36 29, 😀 🔧 🦋 👍 ❤️ (Smiley, Spanner,
  Butterfly, Thumbs Up, Heart). The Public channel → 58 2 35 23 33, 🎺 🦁 🎅 🍌 👓.
- 30 bits are enough for comparing by voice: someone who wants a fake group with the same emoji has to try about
  a billion codes, each costing a scrypt run. They don't protect a short custom code, which can be guessed directly.
- Nothing is sent: each phone computes the fingerprint from its own key.

## Check-ins

A check-in is an ordinary group message, so apps that don't know check-ins still show it as text:

- `✅ I'm safe` means safe. Any message whose text starts with `✅` counts as "safe".
- `🆘 I need help` means needs help. Any message whose text starts with `🆘` counts as "needs help".

A check-in may end with ` · 🔋 NN%`: the sender's battery level (0 to 100) when they sent it, for example
`✅ I'm safe · 🔋 23%`. Apps read the last `🔋 ` in a check-in, followed by 1 to 3 ASCII digits and `%`; anything
else means no battery level. Apps that don't know it just show the text.

A check-in may also end with ` · 📍 LAT,LON` and optionally ` ±Nm`: where the sender was, in decimal degrees (WGS 84,
5 decimals, `.` as the decimal point, `-` for south and west), and the radius in meters their phone was sure of, for
example `✅ I'm safe · 🔋 23% · 📍 45.46420,9.19000 ±12m`. Apps read the last `📍 ` in a check-in; a latitude outside
-90..90 or a longitude outside -180..180 means no position. A phone adds it only if its user turned on location
sharing.

A person's status is their most recent check-in, and so is their battery level. Their position is the one in their
most recent check-in that carried a position.

Check-ins, reports about others and "Are you safe?" requests are group messages. On the Public channel, where anyone
can post, both apps show a text of one of these forms as plain text: no check-in card, no entry in the People list,
no alert and no one-tap answers.

### Needs and head count

A "needs help" check-in may say what is needed, and a check-in of either kind how many people it speaks for:

```
🆘 I need help: injured, water · 👥 3 · 🔋 23% · 📍 45.46420,9.19000 ±12m
✅ I'm safe · 👥 4
```

- **Needs:** `🆘 I need help: ` followed by words from this list, in this order, separated by `, `: `injured`,
  `trapped`, `water`, `food`, `medicine`, `shelter`. Apps show them as Injured, Trapped, Need water, Need food,
  Need medicine, Need shelter. Readers take the part up to the first ` · `, compare words without regard to case and
  skip words they don't know, so newer apps can add needs.
- **Head count:** ` · 👥 N`, N from 1 to 99, after the needs and before the battery level. Readers take the last `👥 `
  followed by 1 or 2 ASCII digits and then a space or the end; anything else means no count.
- A person's needs and head count come from their most recent check-in, like the battery level.
- Apps that don't know them still read the status, battery and position (vectors: `kind: checkin`).
- Size: on MeshCore (packets ≤ 163 bytes) the name and the text together have 99 bytes (with a 12-character device
  id); on Meshtastic (≤ 233 bytes), 169. The first example above is 85 bytes of text, so it fits MeshCore with a name
  of up to 14 bytes. The longest possible check-in (all six needs, 👥 99, battery, position and accuracy) is 128 bytes:
  it still fits Meshtastic, but not MeshCore, and then travels on the other links only.

## Reports about others

Anyone can check in for someone who has no phone or no signal, for example a grandmother they found at the shelter:

```
👤 Grandma is safe
👤 Grandma Rosa needs help: injured, medicine · 👥 2 · 📍 45.46420,9.19000
```

- `👤 `, the person's name, then ` is safe` or ` needs help`. A "needs help" report may list needs like a check-in
  (`: injured, medicine`); either kind may add ` · 👥 N` and ` · 📍 …` (where that person is). There is no battery level.
- The name is one line, at most 24 characters, without `·`. Readers take the part up to the first ` · `; it ends with
  ` is safe`, or contains a last ` needs help` followed by nothing or `: ` and needs. Anything else is not a report.
- The reporter is the message's sender. The text does not repeat it.
- A report does not start with `✅` or `🆘`, so no app, old or new, takes it for the sender's own check-in. Older apps show
  it as text.
- **Name key:** how apps match names (the People list, "Are you safe?", checked people). Names that draw the same
  have the same key:
  1. the name in NFKC, then in lower case;
  2. without the code points that draw nothing: the control characters U+0000–001F and U+007F–009F that aren't white
     space, and Unicode's Default_Ignorable_Code_Point (zero-width characters, direction marks, variation selectors,
     fillers, tags): U+00AD, U+034F, U+061C, U+115F–1160, U+17B4–17B5, U+180B–180F, U+200B–200F, U+202A–202E,
     U+2060–206F, U+3164, U+FE00–FE0F, U+FEFF, U+FFA0, U+FFF0–FFFB, U+1BCA0–1BCA3, U+1D173–1D17A, U+E0000–E0FFF;
  3. in NFKC again (an accent left next to its letter joins it);
  4. with runs of white space made one space, and none at either end. White space is U+0009–000D, U+0020, U+0085,
     U+00A0, U+1680, U+2000–200A, U+2028, U+2029, U+202F, U+205F, U+3000 and the blank Braille pattern U+2800.

  Look-alike letters of another script are not made equal. Vectors: `kind: name-key`.
- **People list:** reports are kept by name key. The latest report for a name wins (its status, needs and count); its
  position stays until a newer report has one. Reports sent by this phone count too. Apps show such an entry as that person's status "reported by" the sender,
  never as the person's own check-in. When a group member whose current name has the same key has their own check-in
  at least as new as the latest report, the report is not shown.
- Vectors: `kind: vouch`.

## "Are you safe?"

A group message that asks everyone, or one person, to check in:

```
❓ Is everyone safe?
❓ Marco, are you safe?
```

- The name is one line, at most 24 characters, without `·`. A message is a request only if it is exactly one of these
  two forms.
- It is for everyone, or for the members whose name has the same key as in "Reports about others". Apps offer them
  one-tap answers, which are ordinary check-ins (`✅ I'm safe`, `🆘 I need help`).
- A one-tap answer goes to the group that asked. If a removal has given that group a new code since the request
  arrived, it goes to the group under its new code (see "Removals and the code"). If the phone no longer has that
  group, the answer isn't sent, and never goes to the group in use instead.
- Vectors: `kind: ask`.

## Photos

A group message can carry one small photo in a **4th plaintext field**, which older readers skip (see "Encryption":
readers ignore bytes after the third field):

- The field has the same 2-byte length prefix. Its first byte is the type, `0x01` = JPEG, followed by the JPEG bytes.
- At most 14000 JPEG bytes, so the packet stays under the 16000-byte cipher limit. Apps shrink photos to fit
  (a few hundred pixels wide) before sending.
- The 3rd field (`text`) is `📷 Photo`, or `📷 ` followed by a caption, so apps that don't know photos show that.
- Readers ignore a 4th field with another type byte, and anything after the 4th field.
- Photos go only to the group, never to the Public channel, and are too big for LoRa radios.

## Places

A place is an ordinary **Public channel** message that tells everyone nearby where to find help, so apps that don't
know places (and the Wi-Fi board) still show it as text:

```
💧 Water: tap at the school gym, bring bottles · 📍 45.46420,9.19000 ±12m
```

- It starts with one of `💧 Water`, `🏠 Shelter`, `🔌 Charging` or `🏥 Medical`, followed by nothing, `:` and a note
  (at most 200 characters), or ` · 📍 …`.
- The position, if any, is written and read exactly like a check-in's (see "Check-ins"). It is where the place is:
  apps add it only when the user says they are at the place.
- Anyone can read places, from any group. Apps sort them by distance and show their age.

### Freshness

Both apps judge a place by the time it was sent (the packet's `ts`): up to 24 hours old it is current; older than
24 hours (86,400,000 ms) it is old and shown greyed; older than 7 days (604,800,000 ms) it is expired and hidden. A
place from a clock that is ahead counts as current. Vectors: `kind: place-freshness`.

## Plus Codes

Positions can also be written as Plus Codes (Open Location Code, github.com/google/open-location-code, Apache License
2.0), which map apps understand and people can read out: 10 digits, for example `8FQFF57R+M2` for 45.46420,9.19000,
an area of about 14 × 14 m.

- Encoding follows the reference: latitude × 25,000,000 and longitude × 8,192,000, each rounded down, then clipped
  (latitude) or wrapped (longitude). Decoding gives the area's corners; its center is the position. Both apps pass rows
  of the reference's `encoding.csv` and `decoding.csv` (`PlusCodeTest`, `PlusCodeTests`) and `kind: pluscode`.
- Plus Codes are not part of messages: check-ins and places keep `📍 LAT,LON`.

### Status text for other apps

"Send via another app" hands another app a plain-text check-in (not encrypted), at most 160 characters, the limit of
satellite messengers:

```
🆘 I need help — Anna. Battery 64%. 45.46420, 9.19000 ±12 m (8FQFF57R+M2) https://osm.org/?mlat=45.46420&mlon=9.19000
```

The status, ` — ` and the name (at most 24 characters) if any, `.`, ` Battery N%.` if known, then, if there is a
position: the coordinates, ` ±N m` if known, the Plus Code in parentheses, and an OpenStreetMap link. Vectors:
`kind: status-share`.

## Delivery receipts

When a phone gets a new group message from someone else, it confirms it with a receipt, so the sender sees
"Delivered to …".

- A receipt is an ordinary packet: marker `0xB3`, a new random id, the reader's clock as `ts`, ttl 16.
- It is sealed exactly like a message, but with the group's **receipt key**: HKDF-SHA256 (RFC 5869) with the group
  key as input key material, no salt, info = the ASCII bytes of `darkproof-receipt-v1`, 32-byte output.
  - Example: for the code `test-group-1` the group key is
    `f5dbd9efb376f8e61a21bd63c2db282b5dfffffd21b1df45ff2af54139a6cd89` and the receipt key is
    `738e7a99ea6284081ccd3d830969a9cb6ad62fd6161f1adedf4d34f13677e479`.
- Plaintext: a signature (see "Signatures"), then `sender` = the reader's member id in the group, `name` = the reader's display name, `text` = the ids of the
  confirmed messages (16 lowercase hex chars each), separated by single spaces, at most 200 per receipt.
- A receipt counts only if its `sender` is in the member list of the epoch whose receipt key opened it (see "Only
  members write in an epoch"), and not from someone removed (see "What the person removed wrote").
- A receipt confirms a message only if this phone wrote that message in the group whose receipt key opened the
  receipt. A member of one saved group can't confirm a message sent to another, and ids that are no message of this
  phone's are not kept.
- A reader counts the first 200 ids of a receipt and reads nothing after them.
- A reader counts once per message, with the time and name of their earliest receipt for it.
- Phones confirm only group messages: not Public channel messages, and not their own. Each message is confirmed
  at most once, when it first arrives. A receipt goes out 2 s after the last message to confirm arrived, or 10 s after
  the first, whichever comes first, plus a random 0–20 s, so a burst of messages (a phone catching up) shares one receipt per group.
- Receipts are not sent over LoRa radios, where airtime is scarce.
- Apps that don't know receipts can't open them with the group or public key, so they store and relay them like any
  other packet and never show them.

## Forwarding rules

- **Flooding:** each packet goes to every connected peer except the one it came from.
- **Deduplication:** a packet already seen (see "The same packet" below) is not shown or stored again. It is forwarded
  again only if it comes with more hops left than the copy the phone holds (next rule).
- **TTL:** forwarded copies carry `ttl - 1`, and only if the received ttl is greater than 1. New messages start at ttl 16.
  A received packet with ttl above 16 (decoding accepts up to 64) is stored and forwarded as if it had ttl 16.
  The ttl is not authenticated, so the first copy to arrive doesn't decide how far a packet goes: when a packet the
  phone still holds for passing on arrives again with a higher ttl, the phone keeps the higher ttl, in its store too,
  and forwards the packet again to every connected peer except the one that copy came from. A copy with the same or a
  lower ttl is ignored. The ttl must rise each time, so one packet is forwarded again at most 15 times.
- **Time:** a packet whose `ts` is more than 7 days old, or more than 10 minutes ahead of the receiver's clock, is
  dropped: not stored, shown or forwarded (it is not marked as seen, so it can come again later). Packets saved on the
  phone that are more than 10 minutes in the future are removed when the app reads its store.
- **Passing on:** up to 500 packets, the newest of the last 7 days. All of them are sent to every newly connected
  peer, except the packets that peer brought itself: it has them, and what came from the relays must not go back up
  (see "Publish"). A packet another peer has since brought with a higher ttl does go to it.
- **Storage on the phone:** every packet seen is saved, so messages are still there after a restart. The store is
  trimmed when the app starts, and whenever it grows 10% past its cap: packets older than 7 days that no saved group
  can read or that are door packets (next rule), Public packets beyond 2,000 (while one sender holds more than 500 of
  them, that sender's oldest go first, otherwise the oldest of all; the senders whose signature the phone can't check
  count together as one sender, and so do all introductions; the phone's own go last), and then, while the store
  holds more than 40 MB (encoded packet sizes) or 20,000 packets: first packets no saved group can read, oldest first,
  then door packets, then the oldest Public messages, and only then the oldest messages and receipts of the saved
  groups.
- **Door packets:** an introduction or a new key that came through a saved group's door is that group's own, kept like
  its messages, only if this phone wrote it or it is signed by someone in the group: in the member list of an epoch
  the phone holds that isn't kept only to read with, and not taken out by a removal that won. The door opens with the
  code alone, so any other is a door packet. Door packets have a room of their own inside the cap, 4 MB and 1,000
  packets for all saved groups together: beyond it their oldest go, at each trim, and the store is also trimmed when
  they reach twice that room. They never push out a message.
- **Sent:** a phone remembers (up to 2,000) which of its own messages it has handed to another phone, a radio or a
  relay, so "Sent" survives a restart.

- **The same packet** means the same id, the same `ts` and the same content (the first 8 bytes of SHA-256 of `ts`, 8
  bytes big-endian, followed by `cipher`). The encryption is bound to `ts`, so a copy with another `ts` can't be opened:
  it is a different packet, like one with other content. The ttl is not part of it. Packets with one id and a different
  `ts` or content are different packets, however many there are, so junk sent first under an id can't stop the real
  packet; the limits on links are what bound them. In the store, the first packet kept under an id goes by that id,
  and any other packet with that id is kept too, under its id and content together (the key above): none replaces
  another, so junk sent first under an id doesn't keep the real packet out of the store either. The queue in front of
  a LoRa radio tells packets apart the same way: the same packet goes over the radio once, whatever its ttl, and junk
  under its id doesn't keep it off. So do the queues for the relays, and what a phone remembers as posted there (see
  "Publish"): junk under an id neither takes the real packet's place nor counts as it.
- **A full queue:** while one sender holds more than a quarter of what is stored, its own oldest packets go first. A
  sender is whoever is at the other end of a link: the IP address on a Wi-Fi network and the device on Bluetooth LE
  (its Bluetooth address; on the iPhone, the identifier iOS gives it), so all links from one address share one
  quarter, at once or one after another; on the other transports, the link. The packets a phone held before a
  restart count together as one sender's, except those a relay brought. Otherwise, while the packets the phone
  didn't write itself hold more than half of what is stored, the oldest of those goes first: no number of links
  pushes out the phone's own packets.
- **Limits on links:** a packet with fewer than 98 bytes of `cipher` is junk and is dropped. A phone takes at most 3,000 new
  packets a minute from one sender (see "A full queue"; relays have their own limit, see "Limits on relays"): closing a
  link and opening another doesn't start a new minute. A copy that is forwarded again because of its higher ttl counts
  as one of them.
- **Keys tried:** a phone tries a packet only with the keys whose mailbox is the first 2 bytes of its id.
- **Node ids prove nothing:** a link claiming the id of a phone already linked doesn't replace that link, unless it comes
  from the same address (Wi-Fi) or was made at the same moment (Bluetooth). Nor does the first link under an id keep
  the phone itself out: a later link from another address (Wi-Fi), or one the other side dialed over another
  connection (Bluetooth), runs beside it. At the link limit, a link at random gives way, whatever its age and at most
  once in 30 s, so that nobody can hold every place, neither by staying nor by making its links anew; on Wi-Fi, the
  address that holds the most links gives up its oldest first.

## Transports

| Transport | Framing |
|---|---|
| Nearby Connections (Android only) | Service id `it.blackout.mesh.v1`, strategy `P2P_CLUSTER`. One `BYTES` payload per packet. |
| Wi-Fi networks (Android and iPhone) | TCP. 4-byte length, then the frame. See below. |
| LoRa via Meshtastic | The packet is `Data.payload` on port 256 (`PRIVATE_APP`), broadcast on channel 0 with hop limit 3. The whole packet must be ≤ 233 bytes. |
| LoRa via MeshCore | Channel data on the `#darkproof` channel, flooded. The whole packet must be ≤ 163 bytes. See below. |
| Bluetooth LE (Android and iPhone) | See below. |
| Internet relays (Android and iPhone) | Nostr events over WebSocket. See below. |
| Apple peer-to-peer (iPhone only) | MultipeerConnectivity. Each packet is one `.reliable` message. See below. |

## Internet relays

While there is internet (Wi-Fi, 4G, satellite), phones also exchange packets through free public **Nostr** relays
(NIP-01), optionally through Tor. The optional GoDark account service does not relay group messages. The relays are one more peer for forwarding: a phone sends
them every packet it has and gets the packets of its mailboxes, so a phone that still has internet during a blackout
bridges its neighbourhood to the rest of the network.

### Mailboxes

The first 2 bytes of a new packet id are its **mailbox**; the other 6 bytes are random. The mailbox of a group is the
first 2 bytes of HMAC-SHA256(group key, `darkproof-relay-mailbox-v1`). Group messages and their delivery receipts use
the group's mailbox; Public messages use the mailbox of the Public channel key. Anyone can read the mailbox from the id
of any packet, so a phone can bridge packets it cannot open. Packets from older apps have random ids.

- Test values: group `test-group-1` → mailbox `6a44`; the Public channel → `9576`.
- Someone who sees packets can tell which ones share a mailbox, not what they say. Many groups share each of the
  65,536 mailboxes. Ids keep 48 random bits, so duplicates stay negligible.

### Events

- **Kind:** `3871`, a regular (stored) kind. It is not in the NIPs list or the registry of kinds, and no events of
  nearby kinds were found on 11 public relays (2026-11).
- **Relays:** `wss://nos.lol`, `wss://relay.damus.io`, `wss://relay.primal.net`, `wss://nostr.mom`,
  `wss://nostr.oxtr.dev`, `wss://relay.ditto.pub`. All free, with no sign-up, payment or proof of work; all keep events
  at least 7 days, and all stored a 22 KB event of this kind from a new key (tested 2026-11-06). Phones use all of them
  at once, so one being down doesn't matter. Relays with a "web of trust" rule refuse large events from new keys.
- **Tags:** `["t", "dp1-<mailbox as 4 hex digits>"]`, `["x", "<packet id>"]` and
  `["expiration", "<created_at + 604800>"]` (NIP-40: relays may delete it after 7 days).
- **Content:** the packet (0xB3 encoding) in standard base64.
- **Date:** `created_at` is the current time rounded down to a multiple of 1024 seconds (about 17 minutes).
- **One set of links per group:** each saved group has its own connection to each relay, its own key and its own
  subscriptions, and so does the Public channel. A group's links start up to 8 s apart at random. A packet this phone
  wrote (a message, receipt, introduction or new key) goes up on the links of its group; every packet it only passes
  on goes up with the Public channel's, whatever mailbox its id names. A sender chooses the id, so the mailbox of
  someone else's packet must never pick the links and key: a neighbour could send junk under a mailbox and see, from
  the key it comes back under, whether the phone holds that mailbox. Nothing a phone sends on one group's links may
  let a relay match them to its other links. Without Tor, relays still see the same internet address on all of them.
  With Tor, the default, each group has its own circuits.
- **Key:** a new random secp256k1 key every time the app starts, for each group, so relays can't link sessions or groups
  by key. The signature (BIP-340) only satisfies the relays: who wrote a message is inside the encrypted packet.
- **Mailboxes of a link:** its group's door and epoch mailboxes, or the Public channel's (`9576`). A link takes only
  packets of these mailboxes, and packets its own `#x` lookup named while that lookup is open (see "Publish"). Any
  other packet a relay sends on it is dropped: a relay chooses what it sends, and a packet planted on one group's link
  must not be passed on, or named on another link.
- **Subscription ids:** the id of a live subscription is `live` and 8 random bytes in hex, that of a lookup `have` and
  8 random bytes in hex, new each time and for each group's links; catch-up ids count up on each link (`cu1`, `cu2`,
  …). No id is made from a clock or anything else the links of one phone share.
- **Subscribe:** on each relay link, one live subscription for all of them,
  `["REQ", <id>, {"kinds": [3871], "#t": ["dp1-<mailbox>", …, "dp1-9576"], "since": now - 604800, "limit": 1}]`
  (`since` a week back so events from phones with a slow clock still match; stored events come from the catch-up).
  When a group's mailboxes change, only that group's links close the subscription and open a new one; the other
  groups' links send nothing, so the change doesn't show on all of a phone's links at the same moment.
- **Catch-up:** then, one mailbox at a time (groups first), `["REQ", <id>, {"kinds": [3871], "#t": ["dp1-<mailbox>"],
  "since": S, "limit": 500}]`, closed after its `EOSE`. When it returns 500 events, whatever they carry (an event
  with no packet in it counts too: anyone can post one under a mailbox's tag), an older page follows with
  `"until"` = the oldest `created_at` received (that value minus 1 if it equals the previous `until`), up to 4 pages
  for a group mailbox and 1 for `9576`. S = the time this phone last caught up that mailbox on that relay minus 25
  minutes (events are dated up to 17 minutes back, and clocks differ), but at most 7 days back. That time, saved on the phone per relay and mailbox, becomes the
  time a catch-up that ended with `EOSE` was started, and then follows the `created_at` of live events (never past
  the phone's clock). A catch-up refused with `CLOSED`, or without `EOSE` within 20 s, moves on and is tried on the
  next link. If the last page of a group mailbox was still full, the mailbox was not read to the end. The phone then
  also saves what it left out: the events from S to the `until` an older page would have had. On each later link, once
  the new events are fetched, it asks for that with `"since"` and `"until"` (never more than 7 days back), with the
  pages that link has left, until a page comes back with fewer than 500 events. For `9576` nothing is saved: its
  newest page is all a phone reads.
- **Publish:** at most one event every 1.5 s, newest packet first, to every connected relay that isn't resting.
  Packets written on this phone (messages and its receipts: the very packets it wrote, see "The same packet", never
  another packet sent under one of their ids) in the last 40 minutes go first, after a random 0–8 s. All
  others (bridging, and older own packets, which may have gone up before the app was killed) wait a random 0–30 s, so
  phones that got the same packet at the same moment don't all find it missing, and are then looked up with
  `["REQ", <id>, {"kinds": [3871], "#x": [<up to 50 packet ids>], "limit": <count>}]`; a packet counts as there only if
  a relay returns an event whose packet has the same `ts` and cipher (the ttl may differ), and only if that event is
  one the packet's recipients get: it has the `t` tag of the packet's own mailbox, no `expiration` earlier than its
  `created_at` + 604800, and a `created_at` no more than 25 minutes before the packet's `ts` (in seconds). Anyone can
  post a copy in an event that no subscription returns: for a packet the phone wrote or got from another peer, such
  a copy counts for nothing, whichever way it arrives, and the phone posts the packet. The others are posted, at
  most one every 4.5 s. A phone's own older packets are looked up before anything it passes on and, if no relay has
  them, go up with its own packets. For the rest, the links that brought them take turns, in the lookups and in
  posting, each link's newest packet first: one link's packets, whatever `ts` they carry, can't take every turn. A packet older than 7 days is never posted (checked again right before posting). A packet
  whose first copy a relay brought never goes back up, whatever event it came in, unless another peer later brings it
  with a higher ttl. This holds after a restart too: a phone remembers which of its packets came from a relay first
  (see "The same packet"), the 1,000 with the newest `ts`, and the 500 it passes on again are its newest, so none of
  those is forgotten. Delivery receipts are sent too.
- **Sent:** a packet counts as on the relays (and, for an own message, as "Sent") only when a relay answers
  `["OK", <event id>, true, …]` (or `false` with a reason starting `duplicate`), or the lookup found it. If every relay
  it went to refuses it, or none accepts it within 30 s, it is queued again, up to 3 tries; after that it waits until
  the relays link again. Each phone remembers up to 3,000 packets it saw accepted.
- **Queues:** at most 500 own packets, 5,000 to look up and 2,000 to post, and at most 8 MiB (encoded packet sizes)
  in each of the last two; when a queue is full, a newer packet
  replaces the oldest one, except that a packet the phone wrote never gives way to one it only passes on, and that
  while the packets one link brought are more than a quarter of a queue, that link's oldest goes first (as in "A full
  queue"). Two packets with one id are two entries.
- **Throttling:** a relay that refuses an event with a reason starting `rate` (`rate-limited:`, `rate limited`),
  `blocked` or `banned` gets no more events from this phone for 10 minutes (it keeps the subscription). With every
  relay resting, packets wait in the queue.
- **Limits on relays:** a relay must answer the WebSocket upgrade with 101 straight away (no 1xx before it). One message
  is at most 1 MiB, and its JSON at most 16 levels deep; a link that sends more is cut or the message ignored. Android
  uses no WebSocket extension, so no message is compressed: an extension a relay names in its answer is not taken up,
  and a frame with a reserved bit set (RSV1 marks a compressed message, whose size says nothing about what it inflates
  to) ends the link. A group's links hold one link to each relay: a second one is never opened beside it, and nothing
  that arrives on a link the phone no longer holds is taken. Each relay gets at most 6,000 messages a minute (`OK`,
  `EOSE` and `CLOSED` aside), across its
  links. Once a link goes over, the phone's saved catch-up time for that relay stops moving, so what was dropped is fetched on the next
  link. An event whose `id` or `pubkey` is not 64 lowercase hex characters is ignored. Relays can't be trusted with
  any of this: when events arrive, their ids and signatures aren't checked, because packets don't rely on them. Only a
  report does (next).
- **Reports:** a reported Public message is hidden on the phone, and a NIP-56 report (kind 1984, tags
  `["e", <event id>, "other"]` and `["p", <author>]`) goes to the relays. It names an event that carried the very
  packet the phone shows (see "The same packet") and that its author signed, never what a relay's frame merely claims.
  For packets of mailbox `9576`, a phone remembers the events whose `id` is the SHA-256 of their own fields (NIP-01)
  and whose `sig` is 128 lowercase hex characters: for each packet, the first such event from each relay, for up to
  2,000 packets. An event that carries another packet under the same packet id is kept apart and never stands in.
  When the report is made, the first remembered event whose signature checks (BIP-340) is named; until there is one,
  the report waits.

### Tor

"Connect through Tor" (on by default) hides the phone's internet address from the relays. Phones are Tor clients
only, never relays. Each group's links use their own SOCKS user name, and Tor keeps different user names on different circuits,
so relays can't tell from the exit address that two groups share a phone.

- **Android:** Tor runs inside the app (tor-android 0.4.9.14, the Tor that Orbot uses) while the switch is on. Every
  relay link and the check below go through its SOCKS port; host names are resolved by Tor. Until it has a circuit,
  nothing goes to the relays.
- **iPhone:** Tor runs inside the app (iCepa's Tor.framework 409.15.3) from the first time it is needed until the app
  quits (Tor can start only once per launch). Relay links and the check use a URL session whose only route is Tor's
  SOCKS port on `localhost`, a free port picked at start.
- **Check:** before linking to any relay, the app fetches `https://check.torproject.org/api/ip` through Tor and goes
  on only if the answer has `"IsTor": true`; otherwise it asks again (every 15 s on Android, 5 s on the iPhone, while
  Tor starts). It asks again whenever all relays are lost.
- **Switching:** turning the relays off, or Tor on or off, ends every relay link made under the old setting, and none
  is made under it afterwards, whatever the app was doing at that moment (a resubscribe after a key change, a
  reconnect).
- Tested 2026-11-06 and 2026-11-09: no connection from either app to a relay or to the check went around Tor.
- **Relays through Tor:** `wss://relay.damus.io`, `wss://relay.primal.net`, `wss://nostr.oxtr.dev`,
  `wss://relay.ditto.pub`, `wss://relay.nostr.net`, `wss://nostr.data.haus`. nos.lol and nostr.mom don't answer Tor
  exits (tested 2026-11-06); the four relays in both lists carry messages between phones with and without Tor.

### Everyone filter

In other people's Public messages and places, each app masks offensive words with bullets (`•`, one per letter)
before showing them. Whole messages are never hidden, so an emergency message with a swear word still gets through.
Your own messages are shown as written. Both apps use the same list (`WordFilter.LIST` / `WordFilter.list`; the tests
pin its SHA-256) and the same rules:

- A word is a run of letters, digits, `@` and `$`; only words with a letter are checked.
- It is compared after removing accents, lowercasing, reading `0 1 3 4 5 7 @ $` as `o i e a s t a s` and dropping
  anything that is not `a`–`z`. Stretched words (a letter 3+ times in a row) are also tried with those runs cut to two
  letters and to one.
- It matches a list entry exactly, or starts with an entry that ends in `*`. Only whole words match, so "Scunthorpe"
  and "puttanesca" stay as written.

### Blocking

Each app lets its user block a sender and hide a message. Both stay on the phone; nothing is sent.

- A block is kept for one channel: the Public channel, or one group (by its group id, which stays when the group's
  code changes). It hides that sender id's messages, places, check-ins and alerts in that channel only. A member id
  means a person only inside its channel, and on the Public channel anyone can write under any id whose key the phone
  doesn't have yet.
- Only the sender of a message whose signature checked can be blocked. A message shown as "not verified yet" can be
  hidden, but not its sender: otherwise someone could get a group member hidden by posting under that member's id.
- A block saved before blocks had a channel still hides that sender id everywhere.

## Wi-Fi networks

Phones on the same Wi-Fi network connect over TCP: a router with no internet, a phone hotspot, a community network or a
long-range rooftop link. Nothing leaves that network.

- **Discovery:** DNS-SD (Bonjour/mDNS), service type `_darkproof._tcp`, instance name = the node id, port = the TCP
  port the device listens on (7777 when it is free). The iPhone lists `_darkproof._tcp` in `NSBonjourServices`.
- **Who connects:** for a discovered device, only the device with the smaller node id connects (comparing bytes), and it
  tries again every 10 s while there is no link. An address the user typed is always connected, and redialed every 5 s.
- **Only the local network:** a discovered device is linked only at an address on the local network: private or
  link-local (10/8, 172.16/12, 192.168/16, 169.254/16, fe80::/10, fc00::/7) or in the same subnet as the phone's
  own address, never loopback (debug builds take it, for tests on a computer), whatever address the DNS-SD answer
  names. A phone takes incoming connections only from such addresses.
  The iPhone's listener and its links to discovered devices never use the mobile network. An address the user typed
  is dialed wherever it is. At most 8 discovered devices are dialed at once, and at most 256 are remembered.
- **Frames:** a 4-byte big-endian length (1–16,064), then the frame. The first frame in each direction is HELLO: the
  ASCII bytes `DPW1`, then the node id in UTF-8 (1–64 bytes). Every later frame is one packet. A link whose first frame
  is not a HELLO, or whose HELLO carries the receiver's own node id, is closed.
- **Restarts and duplicate links:** when a node id that already has a link opens another, the phones keep one:
  - if the two links were dialed by different phones and the older one is less than 10 s old (both dialed at about
    the same time), the link dialed by the smaller node id (comparing bytes) stays, so both phones keep the same one;
  - otherwise the new link replaces the old one, which is closed (after a restart the old one may be dead without
    either side knowing).

  Each link is its own peer for forwarding, so all stored packets go to the new link. A phone doesn't redial a typed
  address while the phone that answered there is linked another way from that address. Node ids prove nothing: a link
  from another address that carries the same node id doesn't count, neither here nor for the 10 s retry of a
  discovered device (on the iPhone, where a discovered device's address isn't known before it is dialed: only a link
  this phone dialed to that device counts).
- **Limits:** at most 32 links, 8 of them from one address (one more takes the place of that address's oldest). At
  most 16 incoming connections wait for their HELLO, 4 of them from one address; one more takes the place of one
  that is still waiting. A frame longer than the limit closes the link, and so does a missing HELLO 10 s after
  connecting. A phone that stops reading is cut when 12 MiB wait for it; when 32 MiB wait for all links together, the
  links with the most waiting are cut, not the one the next packet is for. Turning Wi-Fi networks off closes every
  link and every connection still being set up.
- **iPhone:** the listener and the Bonjour browser start again after any failure (after 2 s, doubling up to 30 s),
  and when the app comes back to the foreground.

## LoRa via MeshCore

MeshCore radios ("companion radio" firmware 1.15 or newer, `FIRMWARE_VER_CODE` ≥ 11) pair with the phone over Bluetooth
LE: Nordic UART service `6E400001-B5A3-F393-E0A9-E50E24DCCA9E`, the phone writes (with response) to `6E400002-…` and
gets notifications from `6E400003-…`. One write or notification is one frame of at most 176 bytes; integers are
little-endian. Source: github.com/meshcore-dev/MeshCore, `examples/companion_radio/MyMesh.cpp` (v1.18).

- **Setup:** `16 03` (device query, protocol 3; the reply `0D` carries the firmware version code in byte 1 and the
  number of channel slots in byte 3), then `01` + 7 zero bytes + `DarkProof` (the legacy MeshCore app-start marker; reply `05`).
- **Channel:** GoDark uses the hashtag channel `#darkproof`, key = the first 16 bytes of SHA-256(`#darkproof`) =
  `835a8265454a846068f204bf5ea81bd3`. The phone reads the slots with `1F <idx>` (reply `12 <idx> <name[32]> <key[16]>`)
  and, if none holds that key, writes it to the first empty slot with `20 <idx> <name[32]> <key[16]>`.
- **Sending:** `3E <idx> FF <type:u16> <packet>`: channel data, flooded (`FF`), data type `0xFF44` (MeshCore's range
  for development; to be registered before release). The packet is ≤ 163 bytes. Reply `00`.
- **Receiving:** the radio pushes `83` when something is queued; the phone sends `0A` until the reply is `0A`. Channel
  data arrives as `1B <snr> 00 00 <idx> <path_len> <type:u16> <len> <packet>`; only `type` `0xFF44` on the GoDark
  slot is read. Other frames are skipped.
- **Pacing:** as for Meshtastic: only packets from the last 30 minutes, one every 20 s, no delivery receipts. At most
  20 packets wait. The packets a phone wrote itself go first, and one it only passes on never takes the place of one
  of them: when the queue is full, the oldest packet passed on makes room.

## Bluetooth LE

This is the only radio link both platforms share without a router. Android phones also keep Nearby. Duplicate packets arriving over both are dropped by the forwarding rules.

### Roles

Every device is a **peripheral**: it advertises and runs a GATT server. It is also a **central**: it scans and connects.

An iPhone in the background advertises in a way Android cannot see. It can still scan and connect out to Android phones, which always advertise.

### Service UUID

`bec33cd5-a64e-4e1a-b8c1-868db67d0df3`, the same for every GoDark device (see "Groups and the Public channel").

- **Advertisement:** connectable. It contains only this 128-bit service UUID, with no device name.

### Characteristics

| Name | UUID | Properties | Direction |
|---|---|---|---|
| RX | `33826aba-0bb0-4dfe-9c1a-86e48726ed62` | write (with response) | central → peripheral |
| TX | `94eb2c34-0e66-4bea-864c-d02a7694a3d5` | notify, with a CCCD descriptor | peripheral → central |

### Connection setup

1. The central connects.
2. It requests the largest ATT MTU and discovers the service.
3. It enables notifications on TX by writing `01 00` to its CCCD.
4. The link is then open in both directions.

### Frames

Each direction carries a stream of frames:

`type` (1 byte) ‖ `length` (2 bytes, big-endian) ‖ `payload` (`length` bytes).

**Chunking:**
- The stream is cut into chunks of at most min(ATT_MTU − 3, 512) bytes. 512 is the longest attribute value BLE allows; Android throws an error above it.
- Each chunk is one write (central → peripheral) or one notification (peripheral → central). Long or prepared writes are not used.
- A side sends its next chunk only after the previous one completes. For the central, that is the write response. For the peripheral, that is the notification-sent callback.

**Frame types:**

| Type | Name | Payload |
|---|---|---|
| 1 | HELLO | Version byte `1`, then the node id: printable ASCII, 1–64 bytes. |
| 2 | PACKET | One packet (see above), up to 18 + 16000 bytes. |

- Each side sends HELLO as its first frame, as soon as it can send. For the central, that is after its CCCD write completes. For the peripheral, that is when notifications get enabled.
- PACKET frames received before the other side's HELLO are ignored.
- An unknown type, a version other than 1, or a bad length means: disconnect.
- After both HELLOs, each side treats the link as a neighbor in the forwarding rules. That includes sending it all stored packets.

### Restarts

An app can restart while the Bluetooth connection stays up: iOS keeps an app's connections when it closes the app to
free memory, and relaunches the app in the background when Bluetooth activity arrives. The restarted app starts the
link over and sends HELLO again.
- A device that gets a HELLO on a link that already has one **from the same node id** answers with its own HELLO again,
  and sends the link all stored packets again (the receiver drops the ones it has), each at most once a minute per
  link, and the stored packets only when the link's send queue is empty. The first repeat is always answered. This
  avoids HELLO ping-pong and endless re-sending. A HELLO with a different node id means: disconnect.
- A central whose peer republishes the GoDark service (the service is invalidated) disconnects and connects again.

### Duplicate links

Two devices may connect to each other twice, once in each direction. When a device sees a second link to a node id it already has a link with, it keeps only one:
- Keep the link whose central has the smaller node id, comparing bytes.
- If both links have the same central, keep the newer one.

Both sides reach the same decision. Either side may close the other link.

This is for two links made at the same moment (less than 10 s apart). After that, the link that is there stays: a
device closes a later link that it dialed itself, or that reached it over the same radio connection. A later link
that the other side dialed over another connection is not closed for its node id: it runs beside the first, since it
may be the real phone and the first one someone who only says its id. If both lead to one phone, that phone closes
the link it dialed.

### Limits

- At most 6 links per device. At the limit, a new link takes the place of the oldest link whose other side hasn't sent
  HELLO after 5 s, if there is one; otherwise of a link at random, at most once in 30 s (see "Node ids prove
  nothing"), and else it is refused.
- A link whose other side sends no HELLO within 10 s of the link opening (central: notifications enabled; peripheral:
  the central subscribed) is closed, and so is a central link still being set up 30 s after dialing. An iPhone cannot
  disconnect a central: it stops serving it, and the link no longer counts toward the limit.
- Each link's send queue holds at most 1 MiB and 1,000 frames. The stored packets go to a new link oldest first and
  only as far as the queue has room (983,040 bytes and 500 packets); the rest, and every later packet in its turn,
  follow as frames leave the queue, so a store larger than the queue is passed on whole. Should the queue still run
  over, the oldest PACKET frames not yet started are dropped (the neighbour gets stored packets again on its next
  link); HELLO frames are never dropped.

## History

- `0xB1`, v0.2: text fields used Java's modified UTF-8, and the code was not normalized.
- `0xB2`, v0.3: standard UTF-8, NFC-normalized group code.
- `0xB2`, v0.4: same packets. Discovery no longer depends on the group code (one Bluetooth LE service UUID, one Nearby service id, no Multipeer group filter), and the Public channel was added. v0.3 and v0.4 devices do not find each other.
- `0xB3`, v0.5: scrypt instead of PBKDF2 for the group key; member ids instead of the device id in `sender`, with a
  member key per group that signs every packet, introductions and person emoji; link ids that change at every app start. Every key, mailbox and fingerprint changes; group codes stay the same. v0.4 and
  v0.5 phones link but drop each other's packets. On its first start, a v0.5 app deletes the packets it stored
  before: nobody can read them any more, so they would only be passed on as noise.
- `0xB3`, v0.6: same packets, new rules (see "Doors and epochs"): the code only opens the door, messages use random
  epoch secrets, introductions also carry an encryption key, and members can be removed. v0.5 phones can't read v0.6
  group messages.
- `0xB3`, 2026-11-09: padding, a link per group, generated codes only, 16 person emoji, weekly encryption keys, ML-KEM
  and new keys split over packets. New keys are types `0x06` and `0x07`; phones on an earlier build can't read them.
  Later the same day: ML-KEM required (iOS 26 or later), joining needs an admin, Tor on by default with a circuit per group,
  blurred times, and a key per message. Then: a packet's position has to be its sender's own, and invites name the admins
  who can let a phone in.
- `0xB3`, 2026-11-13: a message sealed with a message key signs its position and number too, under the tag
  `darkproof-sig-mk-v1`. Phones on an earlier build and on this one drop each other's group messages (they open, the
  signature doesn't check); receipts, introductions, new keys and the Public channel are unchanged. Also new rules,
  with the same bytes: only members write in an epoch, nothing new is shown from someone removed, and someone removed
  adds no keys.

## Apple peer-to-peer (iPhone to iPhone)

iPhones also connect to each other with MultipeerConnectivity, which uses Bluetooth and Apple's peer-to-peer Wi-Fi. Android cannot join these connections.

- **Service type:** `blackout-mesh`. It is listed in the app's `NSBonjourServices`.
- **Peer display name:** the node id.
- **Discovery info:** `v` = `1`. Peers without it are ignored.
- **Who invites:** the device with the smaller node id. The invitation context is the UTF-8 bytes of `blackout-mesh-v1`, and invitations with a different context are declined.
- **Messages:** each packet is sent as one `.reliable` message.
