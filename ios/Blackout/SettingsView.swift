import SwiftUI
import LocalAuthentication
import UserNotifications
import BlackoutCore

// MARK: - Lock

/// "Lock GoDark" (Settings), off unless turned on: the app asks for Face ID, Touch ID or the phone's passcode when it
/// opens, and again after a minute away. While it is on, alerts don't show message text and the app switcher shows a
/// blank screen. Asking for help never needs it: the lock screen has the button, and shortcuts keep working. Main thread.
final class AppLock: ObservableObject {
    static let shared = AppLock()
    @Published private(set) var enabled = UserDefaults.standard.bool(forKey: "appLock")
    private(set) var isLocked = false
    // When the app was left: on a clock nobody can set, which keeps counting while the phone sleeps. The phone's date
    // and time can be set back in Settings, which made the time away negative and skipped the lock.
    private var unlockedOnce = false, leftAt: ContinuousClock.Instant?
    private var window: UIWindow? // above everything, sheets included
    private var covered: [UIWindow] = [] // the app's own windows, out of VoiceOver's and touch's reach while locked
    private weak var keyBefore: UIWindow? // made key again on unlocking
    private var context: LAContext?

    /// False if the phone has no passcode: there would be nothing to ask for.
    var available: Bool { LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) }

    /// Asks for the phone's own unlock, then runs `ok`. If the phone has no passcode any more, nobody is shut out.
    func ask(_ reason: String, ok: @escaping () -> Void) {
        context?.invalidate() // a second tap replaces the first request
        let c = LAContext()
        context = c
        guard c.canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else { return ok() }
        c.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, _ in if success { DispatchQueue.main.async(execute: ok) } }
    }

    /// The switch in Settings.
    func change(_ on: Bool) {
        if on && !available { Nav.shared.toast("Set a passcode on this iPhone first"); return }
        ask(on ? "Turn on the lock" : "Turn off the lock") {
            self.enabled = on; self.unlockedOnce = true
            UserDefaults.standard.set(on, forKey: "appLock")
            Notifier.shared.updateActions()
            if on { UNUserNotificationCenter.current().removeAllDeliveredNotifications() } // alerts already showing still have their text
        }
    }

    func unlock() { ask("Unlock GoDark") { self.unlocked() } }

    private func unlocked() {
        isLocked = false; unlockedOnce = true; leftAt = nil
        hide()
    }

    #if DEBUG
    /// What a successful unlock does, for tests: nobody types a passcode into the system's prompt.
    func unlockForTests() { unlocked() }
    #endif

    func phaseChanged(_ phase: ScenePhase) {
        guard enabled else { return hide() }
        switch phase {
        case .active:
            if isLocked { return }
            let away = leftAt.map { Self.seconds(ContinuousClock.now - $0) }
            if LockGrace.asksAgain(unlockedOnce: unlockedOnce, awaySeconds: away) { lock() } else { hide() }
        case .inactive:
            if !isLocked { show(AnyView(LockCover())) }
        case .background:
            leftAt = ContinuousClock.now
            if !isLocked { show(AnyView(LockCover())) }
        @unknown default: break
        }
    }

    private func lock() {
        isLocked = true
        UIApplication.shared.sendAction(#selector(UIResponder.resignFirstResponder), to: nil, from: nil, for: nil) // the keyboard would stay on top
        show(AnyView(LockView()))
        // The app stays loaded under the lock: VoiceOver, Voice Control, Speak Screen and a keyboard reach only the lock.
        guard let w = window else { return }
        w.rootViewController?.view.accessibilityViewIsModal = true
        if let k = w.windowScene?.keyWindow, k !== w { keyBefore = k }
        w.makeKey()
        for other in w.windowScene?.windows ?? [] where other !== w && !covered.contains(where: { $0 === other }) {
            other.accessibilityElementsHidden = true
            other.isUserInteractionEnabled = false
            covered.append(other)
        }
        UIAccessibility.post(notification: .screenChanged, argument: w.rootViewController?.view)
    }

    private static func seconds(_ d: Duration) -> Double {
        Double(d.components.seconds) + Double(d.components.attoseconds) / 1e18
    }

    private func show(_ v: AnyView) {
        guard let scene = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene }).first else { return }
        let w = window ?? UIWindow(windowScene: scene)
        w.windowLevel = .alert + 1
        w.rootViewController = UIHostingController(rootView: v)
        w.isHidden = false
        window = w
    }

    private func hide() {
        window?.isHidden = true; window = nil
        for w in covered { w.accessibilityElementsHidden = false; w.isUserInteractionEnabled = true }
        covered = []
        if let k = keyBefore, !k.isHidden { k.makeKey() }
        keyBefore = nil
    }
}

/// In the app switcher, and while something else is in front.
private struct LockCover: View {
    var body: some View { ZStack { Theme.bg.ignoresSafeArea(); Logo(size: 88) }.preferredColorScheme(.dark) }
}

/// Nothing of the app shows here, but asking for help doesn't need unlocking.
private struct LockView: View {
    @State private var asking = false
    @State private var sent = false

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea()
            VStack(spacing: 16) {
                Logo(size: 88)
                Text("GoDark is locked").scaledFont(26, .black).foregroundStyle(Theme.text).padding(.bottom, 16)
                Button("Unlock") { AppLock.shared.unlock() }.buttonStyle(PrimaryButton())
                Button("I need help") { asking = true }.buttonStyle(DangerButton())
                if sent { Text("Sent to your group.").scaledFont(16, .semibold).foregroundStyle(Theme.safe) }
            }
            .padding(24)
        }
        .preferredColorScheme(.dark)
        .alert("Send “I need help”?", isPresented: $asking) {
            Button("Send", role: .destructive) { Mesh.shared.engine?.checkIn(.help); sent = true }
            Button("Cancel", role: .cancel) {}
        } message: { Text("Your group gets it right away. You don't need to unlock.") }
    }
}

// MARK: - Settings

/// Settings: the everyday things first, one line each, then the ways messages travel under Advanced.
/// A line with more to it opens its own page; a plain on/off switches right in the list.
struct SettingsSheet: View {
    @ObservedObject var engine: Engine
    @AppStorage("groupName") private var groupName = "My group"
    @CurrentCode private var code
    @AppStorage("name") private var myName = ""
    @AppStorage(LocationService.shareKey) private var shareLocation = false
    @ObservedObject private var loc = LocationService.shared
    @ObservedObject private var notifier = Notifier.shared
    @ObservedObject private var lock = AppLock.shared

    var body: some View {
        SheetPage(title: "Settings") {
            RowCard {
                LinkRow(icon: "person.fill", title: "Your name", value: myName) { NamePage(engine: engine) }
                LinkRow(icon: "person.2.fill", title: "Groups", value: groupNames) { GroupsPage(engine: engine) }
                LinkRow(icon: "person.crop.circle.badge.checkmark", title: "GoDark account", detail: "Optional sign-in and privacy choices") { AccountSettingsPage() }
                SwitchRow(icon: "location.fill", title: "Share my location",
                          detail: shareLocation && loc.denied ? "Location is off for GoDark, so check-ins go out without it."
                                                              : "When you check in, your group sees where you are and can find you with a compass.",
                          detailColor: shareLocation && loc.denied ? Theme.help : Theme.dim,
                          isOn: Binding(get: { shareLocation }, set: { shareLocation = $0; if $0 { LocationService.shared.requestPermission() } }))
                if shareLocation && loc.denied { OpenSettingsButton().padding(.bottom, 8) }
                LinkRow(icon: "bell.fill", title: "Notifications", value: notificationsValue) { NotificationsPage() }
                SwitchRow(icon: "lock.fill", title: "Lock GoDark",
                          detail: lock.enabled && !lock.available ? "This iPhone has no passcode any more, so this lock can't protect GoDark. Set one in the iPhone's Settings."
                              : lock.enabled || lock.available
                              ? "Asks for Face ID or your passcode when you open GoDark. Hides message text in alerts and in the app switcher. “I need help” still works while it's locked."
                              : "Set a passcode on this iPhone first.",
                          detailColor: lock.enabled && !lock.available ? Theme.help : Theme.dim,
                          isOn: Binding(get: { lock.enabled }, set: { lock.change($0) }))
                LinkRow(icon: "questionmark.circle.fill", title: "Help and privacy") { HelpPrivacyPage() }
            }
            Kicker("Advanced").padding(.top, 8).padding(.leading, 4)
            AdvancedRows(engine: engine)
        }
        .onAppear { notifier.refresh() }
    }

    private var groupNames: String {
        ([groupName] + SavedGroups.all().filter { $0.code != code }.map(\.name)).joined(separator: ", ")
    }

    private var notificationsValue: String {
        switch notifier.status {
        case .authorized, .provisional, .ephemeral: return "On"
        case .denied: return "Off"
        default: return "Not set"
        }
    }
}

struct NamePage: View {
    @ObservedObject var engine: Engine
    @CurrentCode private var code
    @AppStorage("name") private var myName = ""
    @State private var draft = ""
    @Environment(\.dismiss) private var dismiss

    private var clean: String { String(draft.trimmingCharacters(in: .whitespacesAndNewlines).prefix(20)) }

    var body: some View {
        SettingsPage(title: "Your name") {
            InputField(label: "Your name", hint: "Shown next to your messages and check-ins.") {
                TextField("", text: $draft).submitLabel(.done).onSubmit(save)
            }
            Button("Save") { save() }.buttonStyle(PrimaryButton()).disabled(clean.isEmpty || clean == myName)
        }
        .onAppear { draft = myName }
    }

    private func save() {
        guard !clean.isEmpty, clean != myName else { return }
        myName = clean
        engine.rejoin(name: clean, code: code)
        Nav.shared.toast("Saved")
        dismiss()
    }
}

struct GroupsPage: View {
    @ObservedObject var engine: Engine
    @AppStorage("groupName") private var groupName = "My group"
    @CurrentCode private var code
    @State private var draft = ""

    private var clean: String { String(draft.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Invite.maxGroupName)) }

    var body: some View {
        SettingsPage(title: "Groups") {
            GroupsCard(engine: engine)
            Card {
                InputField(label: "Name of this group", hint: "Only on this phone. Each person can name it as they like.") {
                    TextField("", text: $draft, prompt: Text(groupName).foregroundColor(Theme.faint)).submitLabel(.done).onSubmit(rename)
                }
                Button("Rename") { rename() }.buttonStyle(GhostButton()).disabled(clean.isEmpty || clean == groupName)
            }
            Card {
                Text("Check your group").scaledFont(17, .bold).foregroundStyle(Theme.text)
                FingerprintView(code: code)
            }
            if let pub = engine.myPublicKey(code) {
                let ix = MemberKey.emoji(pub)
                Card {
                    Text("Your emoji in \(groupName)").scaledFont(17, .bold).foregroundStyle(Theme.text)
                    Text(Fingerprint.emojiLines(ix)).scaledFont(30)
                    Text(Fingerprint.spoken(ix)).scaledFont(13).foregroundStyle(Theme.dim)
                    Text("When someone checks you, read them these. If their phone shows the same, it's really you writing.")
                        .scaledFont(14).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func rename() {
        guard !clean.isEmpty, clean != groupName else { return }
        groupName = clean
        SavedGroups.remember(.init(name: clean, code: code))
        draft = ""
        Nav.shared.toast("Renamed")
    }
}

struct NotificationsPage: View {
    @ObservedObject private var notifier = Notifier.shared

    var body: some View {
        SettingsPage(title: "Notifications") {
            Card {
                HStack {
                    Text("Notifications").scaledFont(17, .bold).foregroundStyle(Theme.text)
                    Spacer()
                    switch notifier.status {
                    case .authorized, .provisional, .ephemeral: Chip("On", Theme.safe)
                    case .denied: Chip("Off")
                    default: EmptyView()
                    }
                }
                Text("Alerts when your groups write or check in, and always when someone needs help. In the background iOS keeps only Bluetooth running, so alerts then come from phones nearby. Made on your phone: no internet needed.")
                    .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                if notifier.status == .notDetermined {
                    Button("Turn on notifications") { notifier.requestPermission() }.buttonStyle(GhostButton())
                } else if notifier.status == .denied {
                    OpenSettingsButton()
                }
            }
        }
        .onAppear { notifier.refresh() }
    }
}

struct HelpPrivacyPage: View {
    var body: some View {
        SettingsPage(title: "Help and privacy") {
            Card {
                Text("Practice and shortcuts").scaledFont(17, .bold).foregroundStyle(Theme.text)
                HStack(spacing: 10) {
                    Button("Practice asking for help") { open(.practice) }.buttonStyle(GhostButton())
                    Button("Shortcut") { open(.shortcut) }.buttonStyle(GhostButton())
                }
                Button("Show the Get ready list") { UserDefaults.standard.set(false, forKey: "hideGetReady"); Nav.shared.toast("It's on Home") }
                    .buttonStyle(GhostButton())
            }
            Card {
                Text("Help and safety").scaledFont(17, .bold).foregroundStyle(Theme.text)
                Text("In Everyone, hold a message to report it or block its sender. Operator and support contact are not configured. Privacy and Terms documents in this source snapshot are drafts.")
                    .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// Closes Settings, then opens the other sheet once this one is gone.
    private func open(_ s: MainView.Sheet) {
        Nav.shared.sheet = nil
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { Nav.shared.sheet = s }
    }
}

// MARK: - Rows

/// Settings lines on one charcoal card.
struct RowCard<Content: View>: View {
    private let content: Content
    init(@ViewBuilder _ content: () -> Content) { self.content = content() }
    var body: some View {
        VStack(alignment: .leading, spacing: 0) { content }
            .padding(.horizontal, 16).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }
}

/// Icon, title and an optional line under it.
struct RowLabel: View {
    let icon: String
    let title: String
    var detail: String? = nil
    var detailColor = Theme.dim

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon).scaledFont(17, .semibold).foregroundStyle(Theme.text).frame(width: 30).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).scaledFont(17, .semibold).foregroundStyle(Theme.text)
                if let detail, !detail.isEmpty {
                    Text(detail).scaledFont(14).foregroundStyle(detailColor).fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

/// A line that opens a page: the current value on the right, then a chevron.
struct LinkRow<Destination: View>: View {
    let icon: String
    let title: String
    var value: String? = nil
    var detail: String? = nil
    @ViewBuilder let destination: () -> Destination

    var body: some View {
        NavigationLink { destination() } label: {
            HStack(spacing: 8) {
                RowLabel(icon: icon, title: title, detail: detail)
                Spacer(minLength: 8)
                if let value, !value.isEmpty {
                    Text(value).scaledFont(15).foregroundStyle(Theme.dim).lineLimit(1)
                }
                Image(systemName: "chevron.right").scaledFont(14, .semibold).foregroundStyle(Theme.decor).accessibilityHidden(true)
            }
            .frame(minHeight: 44)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

/// An on/off line, with what it does (or what is happening) under the title.
struct SwitchRow: View {
    let icon: String
    let title: String
    var detail: String? = nil
    var detailColor = Theme.dim
    @Binding var isOn: Bool

    var body: some View {
        Toggle(isOn: $isOn) { RowLabel(icon: icon, title: title, detail: detail, detailColor: detailColor) }
            .tint(Theme.safe)
            .frame(minHeight: 44)
            .padding(.vertical, 8)
    }
}

/// A page opened from a Settings line: same look as SheetPage, with the back button.
struct SettingsPage<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        ScrollView { VStack(alignment: .leading, spacing: 16) { content() }.padding(20) }
            .scrollDismissesKeyboard(.interactively)
            .background(Theme.bg.ignoresSafeArea())
            .navigationTitle(title).navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Theme.bg, for: .navigationBar)
    }
}
