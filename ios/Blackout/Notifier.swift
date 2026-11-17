import UIKit
import UserNotifications
import BlackoutCore

/// Alerts for new group messages and check-ins, made on this phone (no push server), for every saved group. While
/// GoDark is on screen, the important ones (help, "Are you safe?" for you, another group writing) show as an
/// in-app banner with a haptic instead (Nav.show); otherwise as notifications, also when iOS relaunched GoDark in
/// the background for Bluetooth.
final class Notifier: NSObject, ObservableObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()
    static let askCategory = "ask"
    @Published private(set) var status: UNAuthorizationStatus = .notDetermined

    private var pending: [(m: Message, group: String)] = [] // main thread; group = its saved group's name
    private var task = UIBackgroundTaskIdentifier.invalid
    private let center = UNUserNotificationCenter.current()

    /// The answers under "Are you safe?". With "Lock GoDark" on there is no "I'm safe": the phone's own unlock
    /// isn't GoDark's, and whoever holds an unlocked phone mustn't say it for you (as on Android and in Shortcuts).
    func updateActions() {
        let safe = UNNotificationAction(identifier: "safe", title: "I'm safe", options: [])
        let help = UNNotificationAction(identifier: "help", title: "I need help", options: [.foreground, .destructive])
        let actions = AppLock.shared.enabled ? [help] : [safe, help]
        center.setNotificationCategories([UNNotificationCategory(identifier: Self.askCategory, actions: actions, intentIdentifiers: [])])
    }

    /// Why a one-tap answer wasn't sent, as an alert: "I'm safe" answers without opening GoDark.
    private func notSent(_ body: String) {
        let c = UNMutableNotificationContent()
        c.title = "GoDark"; c.body = body; c.sound = .default
        center.add(UNNotificationRequest(identifier: "not-sent-\(UUID().uuidString)", content: c, trigger: nil))
    }

    func setUp() {
        center.delegate = self
        updateActions()
        refresh()
        #if DEBUG
        if CommandLine.arguments.contains("notifyTest") { // pretend messages arrive just after going to the background
            NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main) { _ in
                var hold = UIBackgroundTaskIdentifier.invalid // like a Bluetooth wake-up: a few seconds to run
                hold = UIApplication.shared.beginBackgroundTask { UIApplication.shared.endBackgroundTask(hold) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) { UIApplication.shared.endBackgroundTask(hold) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.testMessages() }
            }
        }
        if CommandLine.arguments.contains("bannerTest") { // the same, on screen: in-app banners
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) { self.testMessages() }
        }
        #endif
    }

    #if DEBUG
    private func testMessages() {
        let now = Int64(Date().timeIntervalSince1970 * 1000)
        let code = GroupSecrets.shared.current
        received(Message(id: "test-ask-\(now)", ts: now, sender: "test-m", name: "Marco", text: AreYouSafe().text, group: code))
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) {
            self.received(Message(id: "test-help-\(now)", ts: now, sender: "test-l", name: "Lucia",
                                  text: CheckIn.help.text(battery: 9, needs: [.injured, .water], people: 2), group: code))
        }
    }
    #endif

    func refresh() {
        center.getNotificationSettings { s in DispatchQueue.main.async { self.status = s.authorizationStatus } }
    }

    func requestPermission(then: (() -> Void)? = nil) {
        center.requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in
            self.refresh()
            DispatchQueue.main.async { then?() }
        }
    }

    // MARK: - Arriving messages

    /// A group message from someone else just arrived, in any saved group. Main thread.
    func received(_ m: Message) {
        let group = Mesh.shared.engine?.groupName(m.group) ?? "your group"
        Unread.shared.updateAppBadge()
        if UIApplication.shared.applicationState == .active && !AppLock.shared.isLocked { return inApp(m, group: group) }
        // Messages arriving within 2 seconds are posted together: catching up after being out of range can bring
        // dozens at once. iOS gives a few seconds so the batch is posted even if it would suspend the app meanwhile.
        pending.append((m, group))
        guard pending.count == 1 else { return }
        task = UIApplication.shared.beginBackgroundTask(withName: "alerts") { [weak self] in self?.flush() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { self.flush() }
    }

    private var myName: String { UserDefaults.standard.string(forKey: "name") ?? "" }
    private var activeCode: String { GroupSecrets.shared.current ?? "" }

    /// Someone needs help: their own check-in, or a report about someone else.
    private static func help(_ m: Message) -> (who: String, by: String?)? {
        if CheckIn.of(m.text) == .help { return (m.name, nil) }
        if let v = Vouch.of(m.text), v.status == .help { return (v.subject, m.name) }
        return nil
    }

    private static func needsLine(_ m: Message) -> String {
        let needs = CheckIn.of(m.text) == .help ? CheckIn.needs(in: m.text) : Vouch.of(m.text)?.needs ?? []
        let people = CheckIn.people(in: m.text) ?? Vouch.of(m.text)?.people
        var parts = Need.allCases.filter(needs.contains).map(\.label)
        if let people, people > 1 { parts.append("\(people) people") }
        return parts.joined(separator: " · ")
    }

    /// On screen: a banner for what can't wait. Other messages of the group on screen only raise the Chat badge.
    private func inApp(_ m: Message, group: String) {
        let code = m.group ?? ""
        if let h = Self.help(m) {
            let needs = Self.needsLine(m)
            let body = [needs.isEmpty ? nil : needs, h.by.map { "Reported by \($0)" }, "In \(group)"].compactMap { $0 }.joined(separator: " · ")
            Nav.shared.show(Banner(id: m.id, kind: .help, title: "\(h.who) needs help", body: body, group: code, tab: .people))
        } else if let a = AreYouSafe.of(m.text), a.isFor(myName) {
            Nav.shared.show(Banner(id: m.id, kind: .ask, title: a.to == nil ? "\(m.name) asks: is everyone safe?" : "\(m.name) asks if you are safe",
                                   body: "In \(group). Answer with one tap.", group: code, tab: .chat))
        } else if code != activeCode {
            Nav.shared.show(Banner(id: m.id, kind: .message, title: "\(m.name) · \(group)", body: Self.body(m), group: code, tab: .chat))
        }
    }

    private func flush() {
        defer { if task != .invalid { UIApplication.shared.endBackgroundTask(task); task = .invalid } }
        let batch = pending
        pending = []
        guard !batch.isEmpty else { return }
        // Someone asking for help always gets their own alert, and so does a question for you.
        for (m, group) in batch {
            if let h = Self.help(m) {
                let needs = Self.needsLine(m)
                let body = (h.by.map { "Reported by \($0). " } ?? "") + (needs.isEmpty ? "" : needs + ". ") + "Open GoDark to see where and to answer."
                post(m, title: "\(h.who) needs help", body: body, subtitle: group, tab: .people, urgent: true)
            } else if let a = AreYouSafe.of(m.text), a.isFor(myName) {
                post(m, title: a.to == nil ? "\(m.name) asks: is everyone safe?" : "\(m.name) asks if you are safe",
                     body: "Answer with one tap.", subtitle: group, tab: .chat, category: Self.askCategory)
            }
        }
        let rest = batch.filter { Self.help($0.m) == nil && !(AreYouSafe.of($0.m.text)?.isFor(myName) ?? false) }
        var order: [String] = []
        for r in rest where !order.contains(r.m.group ?? "") { order.append(r.m.group ?? "") }
        for code in order { // per group: up to 3 alerts, else one summary
            let msgs = rest.filter { ($0.m.group ?? "") == code }
            if msgs.count <= 3 {
                for (m, group) in msgs { post(m, title: m.name, body: Self.body(m), subtitle: group, tab: CheckIn.of(m.text) == nil ? .chat : .people) }
            } else if let last = msgs.last {
                let names = Array(Set(msgs.map(\.m.name))).sorted()
                let who = names.count <= 2 ? names.joined(separator: " and ") : "\(names[0]), \(names[1]) and \(names.count - 2) more"
                post(last.m, title: "\(msgs.count) new messages in \(last.group)", body: "From \(who).", tab: .chat)
            }
        }
    }

    static func body(_ m: Message) -> String {
        if let c = CheckIn.of(m.text) {
            let battery = CheckIn.battery(in: m.text).map { ", battery \($0)%" } ?? ""
            return c == .safe ? "Is safe\(battery)." : "Needs help\(battery)."
        }
        if let v = Vouch.of(m.text) { return v.status == .safe ? "Reports that \(v.subject) is safe." : "Reports that \(v.subject) needs help." }
        if m.photo != nil { let c = Photo.caption(m.text); return c.isEmpty ? "📷 Photo" : "📷 \(c)" }
        return String(m.text.prefix(300))
    }

    private func post(_ m: Message, title: String, body: String, subtitle: String? = nil, tab: Nav.Tab, urgent: Bool = false,
                      category: String? = nil) {
        let c = UNMutableNotificationContent()
        // With "Lock GoDark" on, nothing about who or what shows on a locked or borrowed phone.
        let hide = AppLock.shared.enabled
        c.title = hide ? "GoDark" : title
        c.body = !hide ? body : category == Self.askCategory ? "Someone asks if you are safe. Open GoDark." : urgent ? "Someone needs help. Open GoDark." : "New message"
        if let subtitle, !hide { c.subtitle = subtitle }
        c.sound = .default
        c.threadIdentifier = urgent ? "help" : "group"
        // Which group and screen to open; a tag stands for the group, so codes never sit in the alert database.
        c.userInfo = ["tab": tab.rawValue, "group": m.group.map(GroupTag.of) ?? ""]
        if let category { c.categoryIdentifier = category }
        if urgent { c.interruptionLevel = .active; c.relevanceScore = 1 }
        if let e = Mesh.shared.engine {
            let codes = Set(e.allMessages.compactMap { $0.isPublic ? nil : $0.group })
            c.badge = NSNumber(value: codes.reduce(0) { $0 + Unread.shared.count($1, in: e.allMessages, me: e.deviceId) })
        }
        center.add(UNNotificationRequest(identifier: m.id, content: c, trigger: nil))
    }

    // MARK: - UNUserNotificationCenterDelegate

    /// On screen, the app itself shows what arrived (in-app banner): no system banner.
    func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done(AppLock.shared.isLocked ? [.banner, .sound] : []) // the lock screen hides the in-app banner
    }

    /// Tapped: opens that group (switching to it if needed) on the right screen. "I'm safe" and "I need help" under a
    /// question answer it in the group that asked, without opening GoDark for "I'm safe".
    func userNotificationCenter(_ c: UNUserNotificationCenter, didReceive r: UNNotificationResponse,
                                withCompletionHandler done: @escaping () -> Void) {
        let info = r.notification.request.content.userInfo
        let tab = (info["tab"] as? Int).flatMap(Nav.Tab.init(rawValue:)) ?? .chat
        // The group that asked, under the code it has now: a removal may have given it a new one since the alert came.
        let answer = GroupTag.answer(for: info["group"] as? String)
        let code: String? = if case .group(let c) = answer { c } else { nil }
        DispatchQueue.main.async {
            Mesh.shared.startIfSetUp()
            switch r.actionIdentifier {
            case "safe":
                // Not offered with the lock on; one from an alert made before it was turned on isn't sent either.
                if AppLock.shared.enabled { self.notSent("Open GoDark and unlock it to say you're safe."); return done() }
                guard answer != .gone else {
                    self.notSent("“I'm safe” wasn't sent: the group that asked isn't on this phone any more. Open GoDark to answer.")
                    return done()
                }
                guard let e = Mesh.shared.engine else { return done() }
                e.checkIn(.safe, group: code, done: done)
            case "help":
                Nav.shared.open(group: code, tab: .people)
                guard answer != .gone else { // never to another group than the one that asked
                    Nav.shared.toast("Not sent: the group that asked isn't on this phone any more.")
                    return done()
                }
                guard let e = Mesh.shared.engine else { return done() }
                e.checkIn(.help, group: code, done: done)
            default:
                Nav.shared.open(group: code, tab: tab, everyone: false)
                done()
            }
        }
    }
}
