import SwiftUI
import BlackoutCore

// MARK: - Model

extension CheckIn {
    var label: String { self == .safe ? "Safe" : "Needs help" }
    var color: Color { self == .safe ? Theme.safe : Theme.help }
}

extension Engine {
    /// This phone's battery level, or nil when unknown (the Simulator has none).
    static var batteryPercent: Int? {
        #if DEBUG
        if let v = UserDefaults.standard.object(forKey: "debugBattery") as? Int { return v } // simctl spawn ... defaults write
        #endif
        UIDevice.current.isBatteryMonitoringEnabled = true
        let level = UIDevice.current.batteryLevel
        return level < 0 ? nil : Int((level * 100).rounded())
    }

    /// Your own most recent check-in in this group.
    var myLastCheckIn: Message? {
        messages.last { !$0.isPublic && $0.sender == deviceId && CheckIn.of($0.text) != nil }
    }
}

/// "just now", "5 min ago", "2 h ago", "3 d ago".
func ago(_ ts: Int64, _ now: Date) -> String {
    let s = max(0, Int(now.timeIntervalSince1970 - Double(ts) / 1000))
    switch s {
    case ..<60: return "just now"
    case ..<3600: return "\(s / 60) min ago"
    case ..<86_400: return "\(s / 3600) h ago"
    default: return "\(s / 86_400) d ago"
    }
}

// MARK: - People tab

struct PeopleView: View {
    @ObservedObject var engine: Engine
    @ObservedObject private var nav = Nav.shared
    @AppStorage("groupName") private var groupName = "My group"

    var body: some View {
        TimelineView(.periodic(from: .now, by: 30)) { t in
            let people = Person.all(in: engine.messages, me: engine.deviceId)
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    HStack(alignment: .top) {
                        ScreenTitle(title: "People", subtitle: people.isEmpty ? groupName :
                            "\(groupName) · \(people.count) \(people.count == 1 ? "person" : "people")")
                        Spacer()
                        Button { nav.sheet = .settings } label: { RoundIcon(symbol: "gearshape.fill") }.accessibilityLabel("Settings")
                    }
                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 12) {
                            BigCheckIn(checkIn: .safe, sending: engine.checkInSending == .safe) {
                                let e = engine
                                e.checkIn(.safe) { nav.toast(e.queuedToast("“I'm safe”")) }
                            }
                            BigCheckIn(checkIn: .help, sending: engine.checkInSending == .help) { nav.sheet = .help }
                        }
                        .disabled(engine.checkInSending != nil)
                        LastCheckIn(engine: engine, now: t.date).padding(.horizontal, 4)
                    }
                    SetupProblemCard(engine: engine)
                    if engine.reach == .none && engine.setupProblem == nil { ConnectionHelp(engine: engine) }
                    if people.isEmpty {
                        NoPeopleCard(groupName: groupName) { nav.sheet = .invite }
                    } else {
                        PeopleList(people: people, engine: engine, now: t.date)
                    }
                    VStack(spacing: 10) {
                        Button { nav.sheet = .askSafe } label: { Label("Ask “Are you safe?”", systemImage: "questionmark.bubble.fill") }
                            .buttonStyle(SecondaryButton())
                        Button { nav.sheet = .vouch } label: { Label("Check in for someone", systemImage: "person.crop.circle.badge.checkmark") }
                            .buttonStyle(SecondaryButton())
                        if !people.isEmpty {
                            Button { nav.sheet = .invite } label: { Label("Invite friends", systemImage: "qrcode") }
                                .buttonStyle(SecondaryButton())
                        }
                    }
                }
                .padding(.horizontal, 20).padding(.top, 8).padding(.bottom, 24)
            }
            .background(Theme.bg.ignoresSafeArea())
        }
    }
}

/// Big green "I'm safe" or red "I need help" tile, in the logo's shape.
struct BigCheckIn: View {
    let checkIn: CheckIn
    var sending = false
    let action: () -> Void

    var body: some View {
        let safe = checkIn == .safe
        Button(action: action) {
            VStack(alignment: .leading, spacing: 18) {
                Image(systemName: safe ? "checkmark.shield.fill" : "sos").scaledFont(30, .bold)
                Text(sending ? "Sending…" : safe ? "I'm safe" : "I need help").scaledFont(21, .heavy)
                    .lineLimit(1).minimumScaleFactor(0.7)
            }
            .foregroundStyle(safe ? Color.black : .white)
            .frame(maxWidth: .infinity, minHeight: 132, alignment: .bottomLeading).padding(18)
            .background(VaultShape(cut: 28, radius: 32, small: 6).fill(checkIn.color))
            .contentShape(VaultShape(cut: 28, radius: 32, small: 6))
        }
        .buttonStyle(PressScale())
        .accessibilityLabel(sending ? "Sending" : safe ? "I'm safe" : "I need help")
        .accessibilityHint(safe ? "Tells your group you're safe" : "Asks your group for help")
    }
}

/// "Your last check-in: safe, 12 min ago."
struct LastCheckIn: View {
    @ObservedObject var engine: Engine
    let now: Date

    var body: some View {
        if engine.checkInSending != nil {
            Text("Getting your position, then sending…").scaledFont(14, .semibold).foregroundStyle(Theme.text)
        } else if let m = engine.myLastCheckIn, let c = CheckIn.of(m.text) {
            Text("Your last check-in: \(c.label.lowercased()), \(ago(m.ts, now)).").scaledFont(14).foregroundStyle(Theme.dim)
        } else {
            Text("One tap tells your group how you are.").scaledFont(14).foregroundStyle(Theme.dim)
        }
    }
}

/// Shown while nobody from the group has written yet.
struct NoPeopleCard: View {
    let groupName: String
    let invite: () -> Void

    var body: some View {
        Card {
            Text("No one from \(groupName) yet").scaledFont(20, .bold).foregroundStyle(Theme.text)
            Text("Invite friends with a QR code, then keep GoDark open near each other. People show up here once they write.")
                .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
            Button(action: invite) { Label("Invite friends", systemImage: "qrcode") }.buttonStyle(PrimaryButton())
        }
    }
}

/// People in one card, divided by hairlines.
struct PeopleList: View {
    let people: [Person]
    @ObservedObject var engine: Engine
    let now: Date
    @CurrentCode private var code
    @State private var finding: Person?
    @State private var checking: Person?

    var body: some View {
        VStack(spacing: 0) {
            ForEach(people) { p in
                PersonRow(person: p, byMe: p.reporterId == engine.deviceId, now: now,
                          newKey: !p.isReport && engine.newKeyFor(code, p.id, p.name), find: { finding = p },
                          open: p.isReport ? nil : { checking = p })
                if p.id != people.last?.id { Rectangle().fill(Theme.line).frame(height: 1).padding(.leading, 76) }
            }
        }
        .sheet(item: $checking) { PersonCheckSheet(engine: engine, person: $0, code: code) }
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
        .sheet(item: $finding) { FindSheet(person: $0) }
    }
}

struct PersonRow: View {
    let person: Person
    var byMe = false
    let now: Date
    var newKey = false        // a checked person's name with another key (spec "Person emoji")
    var find: () -> Void = {} // opens the compass, for people who shared their position
    var open: (() -> Void)? = nil // their emoji check; reports have none

    private var status: (String, Color) {
        guard let c = person.checkIn else { return ("Last heard \(ago(person.lastTs, now))", Theme.dim) }
        if person.isReport {
            let by = byMe ? "by you" : "by \(person.reportedBy ?? "someone")"
            return ("\(c.label) (reported \(by)) · \(ago(person.checkInTs, now))", c.color)
        }
        return ("\(c.label) · \(ago(person.checkInTs, now))", c.color)
    }

    var body: some View {
        let s = status
        let extra = needsText(person.checkIn == .help ? person.needs : [], people: person.people)
        HStack(spacing: 14) {
            Group {
                if person.isReport {
                    Image(systemName: "person.fill").scaledFont(18, .bold).foregroundStyle(Theme.dim)
                        .frame(width: 46, height: 46).background(Circle().fill(Theme.tile))
                        .overlay(Circle().stroke(person.checkIn?.color ?? .clear, style: StrokeStyle(lineWidth: 2, dash: [4, 3])).padding(-3))
                } else {
                    Text(String(person.name.prefix(1)).uppercased()).scaledFont(18, .bold).foregroundStyle(Theme.text)
                        .frame(width: 46, height: 46).background(Circle().fill(Theme.tile))
                        .overlay(Circle().stroke(person.checkIn?.color ?? .clear, lineWidth: 2.5).padding(-3))
                }
            }
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(person.name).scaledFont(17, .semibold).foregroundStyle(Theme.text).lineLimit(1)
                Text(s.0).scaledFont(14, .medium).foregroundStyle(s.1).fixedSize(horizontal: false, vertical: true)
                if !extra.isEmpty { Text(extra).scaledFont(14, .semibold).foregroundStyle(Theme.text).fixedSize(horizontal: false, vertical: true) }
                if newKey { Text("New key: check their emoji").scaledFont(14, .semibold).foregroundStyle(Theme.help) }
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 6) {
                if let b = person.battery { BatteryLabel(percent: b) }
            }
            if person.spot != nil {
                Button(action: find) { RoundIcon(symbol: "location.north.fill") }
                    .accessibilityLabel("Find \(person.name)")
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 12)
        .contentShape(Rectangle())
        .onTapGesture { if let open { open() } else if person.spot != nil { find() } }
        .accessibilityElement(children: .combine)
        .accessibilityAction(named: "Find \(person.name)") { if person.spot != nil { find() } }
        .accessibilityAction(named: "Check \(person.name)'s emoji") { open?() }
    }
}

/// Battery level from someone's check-in. Red at 20% or less: their phone may soon go off.
struct BatteryLabel: View {
    let percent: Int

    var body: some View {
        let low = percent <= 20
        HStack(spacing: 4) {
            Image(systemName: percent <= 10 ? "battery.0percent" : percent <= 35 ? "battery.25percent" :
                    percent <= 60 ? "battery.50percent" : percent <= 85 ? "battery.75percent" : "battery.100percent")
            Text("\(percent)%")
        }
        .scaledFont(13, .semibold)
        .foregroundStyle(low ? Theme.help : Theme.dim)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Battery \(percent) percent")
    }
}

// MARK: - Connection help

/// Shown while nothing carries messages yet (no phone, relay or radio): what to check.
struct ConnectionHelp: View {
    @ObservedObject var engine: Engine

    var body: some View {
        Card {
            Text("No one in range yet").scaledFont(20, .bold).foregroundStyle(Theme.text)
            tip("iphone.radiowaves.left.and.right",
                "Open GoDark on both phones and stay within about 10–50 m. Walls cut the range: try outside or by a window.")
            tip("wifi", "On the same Wi-Fi or hotspot, phones also connect with no internet.")
            tip("point.3.connected.trianglepath.dotted",
                "Farther away? Messages hop through any phone with GoDark in between. For kilometers, pair a LoRa radio.")
        }
    }

    private func tip(_ icon: String, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Image(systemName: icon).foregroundStyle(Theme.text).frame(width: 22).accessibilityHidden(true)
            Text(text).scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A person's 8 emoji (spec/FORMAT.md, "Person emoji"): compared with the emoji on their phone, then marked as checked.
/// Warns when a checked person's name now comes with another key.
struct PersonCheckSheet: View {
    @ObservedObject var engine: Engine
    let person: Person
    let code: String
    @State private var checked = false
    @State private var finding = false
    @State private var askAdmin = false
    @State private var askRemove = false
    @Environment(\.dismiss) private var dismiss

    private func note(_ ok: Bool, _ done: String) { Nav.shared.toast(ok ? done : "Not everyone's keys have reached this phone yet. Try again when they're in reach.") }

    var body: some View {
        let pub = engine.publicKey(of: person.id, in: code)
        let newKey = engine.newKeyFor(code, person.id, person.name)
        SheetPage(title: person.name) {
            Card {
                HStack {
                    Text(newKey ? "New key for \(person.name)" : "Check \(person.name)").scaledFont(18, .bold)
                        .foregroundStyle(newKey ? Theme.help : Theme.text)
                    Spacer()
                    if checked { Chip("Checked", Theme.safe) }
                }
                if newKey {
                    Text("You checked \(person.name) before, with another key. If \(person.name) didn't reinstall GoDark or reset their phone, someone else may be using their name. Check their emoji before you trust these messages.")
                        .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                }
                if let pub {
                    let ix = MemberKey.emoji(pub)
                    Text(Fingerprint.emojiLines(ix)).scaledFont(30)
                    Text(Fingerprint.spoken(ix)).scaledFont(13).foregroundStyle(Theme.dim)
                    if checked {
                        Text("You compared these with \(person.name)'s phone.").scaledFont(15).foregroundStyle(Theme.dim)
                    } else {
                        Text("Meet \(person.name) or call them. They open Settings › Groups and read you “Your emoji”. If they're the same as these, tap They match.")
                            .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                        Button("They match") { engine.markChecked(code, person.id, person.name); checked = true }.buttonStyle(GhostButton())
                    }
                } else {
                    Text("\(person.name)'s key hasn't reached this phone yet, so their messages show “Not verified yet”. It comes by itself when their phone or the internet is in reach.")
                        .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                }
            }
            if person.spot != nil {
                Button { finding = true } label: { Label("Find \(person.name)", systemImage: "location.north.fill") }.buttonStyle(PrimaryButton())
            }
            let admin = engine.isAdmin(code, person.id)
            if admin { Text("\(person.name) is an admin of this group.").scaledFont(15).foregroundStyle(Theme.dim) }
            if person.id != engine.deviceId, engine.isAdmin(code, engine.deviceId), engine.inGroup(code, person.id), !engine.removed(code) {
                if !admin { Button("Make admin") { askAdmin = true }.buttonStyle(SecondaryButton()) }
                Button("Remove from group") { askRemove = true }.buttonStyle(SecondaryButton())
            }
        }
        .onAppear { checked = engine.isChecked(code, person.id) }
        .sheet(isPresented: $finding) { FindSheet(person: person) }
        .alert("Make \(person.name) an admin?", isPresented: $askAdmin) {
            Button("Make admin") { engine.makeAdmin(code, person.id) { note($0, "\(person.name) is now an admin") } }
            Button("Cancel", role: .cancel) {}
        } message: { Text("\(person.name) will be able to remove people and make others admins. The group sees this.") }
        .alert("Remove \(person.name)?", isPresented: $askRemove) {
            Button("Remove", role: .destructive) { engine.remove(code, person.id) { ok in note(ok, "\(person.name) was removed"); if ok { dismiss() } } }
            Button("Cancel", role: .cancel) {}
        } message: { Text("Everyone else gets a new key and a new invite code, and old invites stop working. \(person.name) can't read anything from now on. The group sees who removed them.") }
    }
}
