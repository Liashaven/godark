import SwiftUI
import AVFoundation
import BlackoutCore

/// Which invite link QR codes and shared invites carry.
enum InviteLinks {
    /// Web invites stay disabled until a real GoDark join page and verified platform association files exist.
    static let useWebLinks = false
    /// Empty until an actual public app/info URL is configured; never send a placeholder domain.
    static let download = ""

    static func link(name: String, code: String, pins: String) -> URL {
        useWebLinks ? Invite.webUrl(name: name, code: code, pins: pins) : Invite.url(name: name, code: code, pins: pins)
    }

    /// The group name and code in invite `link` and the admins it names, or nil if it isn't one. Reading a link keeps
    /// nothing: the admins are saved only when the user joins with it (`GroupSecrets.joining`).
    static func read(_ link: String) -> PendingInvite? {
        guard let i = Invite.parse(link) else { return nil }
        return PendingInvite(name: i.name, code: i.code, pins: Invite.pins(link))
    }

    /// The admins to keep when the user joins `code`: those `invited` names, if the code is still the one that link carried.
    static func pins(_ invited: PendingInvite?, for code: String) -> String { invited?.code == code ? invited?.pins ?? "" : "" }
}

/// Groups this phone has been in, so random codes are never lost when switching. Stored only on this phone.
/// The code of the group in use, for the screens: `@CurrentCode private var code`.
@propertyWrapper struct CurrentCode: DynamicProperty {
    @ObservedObject private var store = GroupSecrets.shared
    var wrappedValue: String {
        get { store.code }
        nonmutating set { store.setCode(newValue) }
    }
}

enum SavedGroups {
    struct Entry: Codable, Identifiable, Hashable { var name: String; var code: String; var id: String { code } }
    static let max = 20 // like Android

    static func all() -> [Entry] { GroupSecrets.shared.groups }

    static func remember(_ e: Entry) {
        let list = [e] + all().filter { $0.code != e.code }
        GroupSecrets.shared.setGroups(Array(list.prefix(max)))
    }

    /// Someone was removed from a group: it now has a new code (spec "Removing and the code"). Its name stays.
    static func replaceCode(_ old: String, _ new: String) {
        GroupSecrets.shared.setGroups(all().map { Entry(name: $0.name, code: $0.code == old ? new : $0.code) })
    }

    /// The saved group that would be dropped to make room for `code`, if the list is full.
    static func wouldDrop(for code: String) -> Entry? {
        let list = all()
        guard list.count >= max, !list.contains(where: { $0.code == code }) else { return nil }
        return list.last
    }

    /// `old` turned out to be an old code of the saved group whose code is `now`: that group is shown in its place, and `old` isn't kept.
    static func follow(_ old: String, _ now: String) {
        guard let g = all().first(where: { $0.code == now }) else { return }
        GroupSecrets.shared.setGroups(all().filter { $0.code != old })
        if GroupSecrets.shared.current == old { GroupSecrets.shared.setCode(now); UserDefaults.standard.set(g.name, forKey: "groupName") }
    }

    /// Makes [code] this phone's group: keeps the old one in the list, saves the new one, and shows its messages.
    /// `pins`: the admins the invite it came from names; kept if this phone doesn't have the code yet.
    static func switchTo(groupName: String, code: String, engine: Engine, pins: String = "") {
        GroupSecrets.shared.joining(code, pins: pins)
        let d = UserDefaults.standard
        if let old = GroupSecrets.shared.current, !old.isEmpty, old != code {
            remember(Entry(name: d.string(forKey: "groupName") ?? "My group", code: old))
        }
        remember(Entry(name: groupName, code: code))
        GroupSecrets.shared.setCode(code); d.set(groupName, forKey: "groupName")
        engine.rejoin(name: engine.name, code: code)
    }

    /// "Anna's group" (or "Anna's group 2" if that name is taken), the name a new group gets when none is typed.
    static func defaultName(for me: String) -> String {
        let n = me.trimmingCharacters(in: .whitespacesAndNewlines)
        let base = String((n.isEmpty ? "My group" : "\(n)'s group").prefix(Invite.maxGroupName - 3))
        let taken = Set(all().map(\.name) + [UserDefaults.standard.string(forKey: "groupName") ?? ""])
        guard taken.contains(base), GroupSecrets.shared.current?.isEmpty == false else { return base }
        return (2...99).lazy.map { "\(base) \($0)" }.first { !taken.contains($0) } ?? base
    }
}

// MARK: - Fingerprint

/// "Compare these with the other phone: 🐶 😀 🐼 🔨 🐧": the group's fingerprint, worked out off the main thread once.
struct FingerprintView: View {
    let code: String
    @State private var indices: [Int]?
    private static var cache: [String: [Int]] = [:] // main thread

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Compare these with the other phone:").scaledFont(15, .semibold).foregroundStyle(Theme.text)
            Text(indices.map(Fingerprint.emojiText) ?? "…").scaledFont(30).textSelection(.enabled)
            if let indices { Text(Fingerprint.spoken(indices)).scaledFont(13).foregroundStyle(Theme.dim) }
            Text("Different emoji: you are not in the same group. Check the code or scan the QR again.")
                .scaledFont(13).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(indices.map { "Group check. Compare with the other phone: \(Fingerprint.spoken($0))" } ?? "Group check, working it out")
        .task(id: code) {
            if let c = Self.cache[code] { indices = c; return }
            let c = code
            let r = await Task.detached(priority: .userInitiated) { Fingerprint.forCode(c) }.value
            Self.cache[c] = r
            indices = r
        }
    }
}

// MARK: - Invite

struct InviteSheet: View {
    let groupName: String
    let code: String
    @State private var showCode = false
    @AppStorage("didInvite") private var didInvite = false
    @State private var pins: String? // nil until the group's keys are loaded: a group just created can get here first
    private var url: URL { InviteLinks.link(name: groupName, code: code, pins: pins ?? "") }
    private var inviteMessage: String {
        let base = "Join my group \(groupName) on GoDark. Tap the link, or type this code in GoDark: \(code)"
        return InviteLinks.download.isEmpty ? base : "\(base)\nGoDark info: \(InviteLinks.download)"
    }

    var body: some View {
        SheetPage(title: "Invite") {
            VStack(spacing: 20) {
                VStack(spacing: 6) {
                    Text("Invite to \(groupName)").scaledFont(28, .heavy).foregroundStyle(Theme.text)
                        .multilineTextAlignment(.center).lineLimit(2).minimumScaleFactor(0.6)
                    Text("Your friend points their phone camera at this code, or scans it in GoDark.")
                        .scaledFont(15).foregroundStyle(Theme.dim).multilineTextAlignment(.center)
                }
                if pins != nil, let qr = Invite.qr(url) {
                    Image(uiImage: qr).interpolation(.none).resizable().scaledToFit()
                        .padding(20)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 28, style: .continuous))
                        .frame(maxWidth: 280)
                        .accessibilityLabel("Invite QR code for \(groupName)")
                }
                ShareLink(item: url, subject: Text("Join \(groupName) on GoDark"),
                          message: Text(inviteMessage)) {
                    Label("Send invite", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(PrimaryButton())
                .disabled(pins == nil)
                .simultaneousGesture(TapGesture().onEnded { didInvite = true })
                Text("AirDrop works without internet.").font(.footnote).foregroundStyle(Theme.dim)
            }
            .frame(maxWidth: .infinity)
            Card { FingerprintView(code: code) }
            Card {
                Text("Or tell them the code").scaledFont(17, .bold).foregroundStyle(Theme.text)
                if showCode {
                    Text(code).scaledFont(22, .bold, design: .monospaced).foregroundStyle(Theme.text)
                        .textSelection(.enabled)
                    Button("Copy code") { UIPasteboard.general.setItems([["public.utf8-plain-text": code]], options: [.expirationDate: Date().addingTimeInterval(60), .localOnly: true]); didInvite = true; Nav.shared.toast("Code copied") }
                        .buttonStyle(GhostButton())
                } else {
                    Button("Show code") { showCode = true }.buttonStyle(GhostButton())
                }
                Label("Anyone with this QR or code can read the group. Share it only with people you trust.", systemImage: "lock.fill")
                    .font(.footnote).foregroundStyle(Theme.dim)
            }
        }
        .task(id: code) {
            for _ in 0..<40 {
                if let p = Mesh.shared.engine?.invitePins(code) { pins = p; return }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
            pins = ""
        }
        .task { // showing the QR for a few seconds counts as inviting (for the Get ready list)
            try? await Task.sleep(nanoseconds: 4_000_000_000)
            didInvite = true
        }
    }
}

// MARK: - QR scanner

/// Scans an invite QR code with the camera (darkproof:// and darkproof.app/join links).
struct QRScannerSheet: View {
    let found: (PendingInvite) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var problem: (text: String, settings: Bool)?
    @State private var notInvite = false

    var body: some View {
        NavigationStack {
            ZStack {
                Color.black.ignoresSafeArea()
                if let problem {
                    VStack(spacing: 16) {
                        Image(systemName: "camera.fill").scaledFont(30, .semibold).foregroundStyle(Theme.dim)
                        Text(problem.text).scaledFont(17).foregroundStyle(Theme.text).multilineTextAlignment(.center)
                        if problem.settings { OpenSettingsButton() }
                    }
                    .padding(32)
                } else {
                    QRCamera(onCode: { s in
                        if let i = InviteLinks.read(s) {
                            UINotificationFeedbackGenerator().notificationOccurred(.success)
                            found(i); dismiss()
                        } else { notInvite = true }
                    }, onProblem: { problem = $0 })
                    .ignoresSafeArea()
                    VStack {
                        Spacer()
                        RoundedRectangle(cornerRadius: 28, style: .continuous).stroke(Color.white, lineWidth: 3)
                            .frame(width: 250, height: 250).accessibilityHidden(true)
                        Spacer()
                        Text(notInvite ? "This QR code isn't a GoDark invite." : "Point the camera at the invite QR code.")
                            .scaledFont(16, .semibold).foregroundStyle(Theme.text)
                            .padding(.horizontal, 18).padding(.vertical, 12).background(Color.black.opacity(0.7), in: Capsule())
                            .padding(.bottom, 40)
                    }
                }
            }
            .navigationTitle("Scan invite").navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(Theme.bg, for: .navigationBar)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
        }
        .preferredColorScheme(.dark)
        .tint(Theme.text)
    }
}

/// The camera preview that reads QR codes. Reports a missing camera or refused access instead.
struct QRCamera: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    let onProblem: ((text: String, settings: Bool)) -> Void

    func makeUIViewController(context: Context) -> Controller { Controller(onCode: onCode, onProblem: onProblem) }
    func updateUIViewController(_ vc: Controller, context: Context) {}

    final class Controller: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
        private let onCode: (String) -> Void
        private let onProblem: ((text: String, settings: Bool)) -> Void
        private let session = AVCaptureSession()
        private let q = DispatchQueue(label: "qr")
        private var preview: AVCaptureVideoPreviewLayer?
        private var last = ""

        init(onCode: @escaping (String) -> Void, onProblem: @escaping ((text: String, settings: Bool)) -> Void) {
            self.onCode = onCode; self.onProblem = onProblem
            super.init(nibName: nil, bundle: nil)
        }
        required init?(coder: NSCoder) { fatalError("not used") }

        override func viewDidLoad() {
            super.viewDidLoad()
            view.backgroundColor = .black
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .authorized: configure()
            case .notDetermined:
                AVCaptureDevice.requestAccess(for: .video) { ok in
                    DispatchQueue.main.async { ok ? self.configure() : self.denied() }
                }
            default: denied()
            }
        }

        private func denied() { onProblem(("Camera access is off for GoDark. Turn it on in Settings, or type the code instead.", true)) }

        private func configure() {
            guard let cam = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: cam),
                  session.canAddInput(input) else {
                onProblem(("This device has no camera. Type the code instead.", false)); return
            }
            session.addInput(input)
            let out = AVCaptureMetadataOutput()
            guard session.canAddOutput(out) else { onProblem(("The camera can't read codes right now.", false)); return }
            session.addOutput(out)
            out.setMetadataObjectsDelegate(self, queue: .main)
            out.metadataObjectTypes = [.qr]
            let p = AVCaptureVideoPreviewLayer(session: session)
            p.videoGravity = .resizeAspectFill
            p.frame = view.bounds
            view.layer.addSublayer(p)
            preview = p
            q.async { self.session.startRunning() }
        }

        override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
        override func viewWillDisappear(_ animated: Bool) { super.viewWillDisappear(animated); q.async { self.session.stopRunning() } }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard let s = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue, s != last else { return }
            last = s
            onCode(s)
        }
    }
}

// MARK: - Join and create

/// Group code (typed, pasted, or from a scanned or pasted invite link) and an optional group name.
struct CodeEntry: View {
    @Binding var code: String
    @Binding var groupName: String
    /// The invite link the code came from, with the admins it names (`InviteLinks.pins`).
    @Binding var invited: PendingInvite?
    var focusCode: FocusState<Bool>.Binding? = nil
    @State private var scanning = false
    @State private var fromLink: String?

    static func warning(_ code: String) -> String? {
        let c = Invite.normalizeCode(code)
        if c.isEmpty { return nil }
        if !Invite.isGeneratedCode(c) { return "That isn't a code GoDark made. Codes look like XXXX-XXXX-XXXX-XXXX." }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Button { scanning = true } label: { Label("Scan invite QR code", systemImage: "qrcode.viewfinder") }
                .buttonStyle(SecondaryButton())
            InputField(label: "Group code", hint: fromLink.map { "From the invite link for “\($0)”." } ?? "Or paste the invite link.") {
                let f = TextField("", text: $code, prompt: Text("XXXX-XXXX-XXXX-XXXX").foregroundColor(Theme.faint)).autocorrectionDisabled()
                    .textInputAutocapitalization(.characters).autocorrectionDisabled().submitLabel(.done)
                if let focusCode { f.focused(focusCode) } else { f }
            }
            if let w = Self.warning(code) {
                Label(w, systemImage: "exclamationmark.triangle.fill").scaledFont(14).foregroundStyle(Theme.dim)
                    .fixedSize(horizontal: false, vertical: true)
            }
            InputField(label: "Group name (optional)", hint: "Shown only on this phone. You can change it later.") {
                TextField("", text: $groupName, prompt: Text("Group").foregroundColor(Theme.faint)).submitLabel(.done)
            }
        }
        .onChange(of: code) { new in
            guard let i = InviteLinks.read(new) else { return } // a pasted invite link: keep its code, offer its name
            code = i.code; fromLink = i.name; invited = i
            if groupName.trimmingCharacters(in: .whitespaces).isEmpty { groupName = i.name }
        }
        .sheet(isPresented: $scanning) {
            QRScannerSheet { i in code = i.code; fromLink = i.name; groupName = i.name; invited = i }
        }
    }
}

/// Join another group from Settings or the group list: asks for a name, keeps the name of a group saved before.
struct JoinGroupSheet: View {
    @ObservedObject var engine: Engine
    var prefill: PendingInvite? = nil
    @Environment(\.dismiss) private var dismiss
    @CurrentCode private var current
    @AppStorage("groupName") private var currentName = "My group"
    @State private var code = ""
    @State private var name = ""
    @State private var invited: PendingInvite?

    private var clean: String { Invite.normalizeCode(code) }
    private var saved: SavedGroups.Entry? { SavedGroups.all().first { $0.code == clean } }

    var body: some View {
        SheetPage(title: "Join a group", close: "Cancel") {
            Text("Scan your friend's invite QR, or type their code.").scaledFont(15).foregroundStyle(Theme.dim)
            CodeEntry(code: $code, groupName: $name, invited: $invited)
            if clean == current && !clean.isEmpty {
                Label("You're already in this group: \(currentName).", systemImage: "checkmark.circle.fill")
                    .scaledFont(15, .semibold).foregroundStyle(Theme.safe)
            } else if let s = saved {
                Text("You were in this group before. It keeps its name, \(s.name).").scaledFont(14).foregroundStyle(Theme.dim)
            } else if !clean.isEmpty, name.caseInsensitiveCompare(currentName) == .orderedSame || SavedGroups.all().contains(where: { $0.name.caseInsensitiveCompare(name) == .orderedSame }) {
                Text("You already have a group called \(name), and this code is for a different one. Someone could be copying the name to get your check-ins. Only join if you trust who sent it.")
                    .scaledFont(14).foregroundStyle(Theme.help).fixedSize(horizontal: false, vertical: true)
            } else if let drop = SavedGroups.wouldDrop(for: clean), !clean.isEmpty {
                Text("You have \(SavedGroups.max) groups saved. Joining removes the oldest, \(drop.name), from this phone.")
                    .scaledFont(14).foregroundStyle(Theme.help).fixedSize(horizontal: false, vertical: true)
            }
            Button("Join group") { join() }
                .buttonStyle(PrimaryButton())
                .disabled(!Invite.isGeneratedCode(clean) || clean == current)
            Text("Switching shows the other group's messages. This group's messages stay on the phone.")
                .font(.footnote).foregroundStyle(Theme.dim)
        }
        .onAppear { if let p = prefill { code = p.code; name = p.name; invited = p } }
    }

    private func join() {
        let typed = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Invite.maxGroupName))
        let n = saved?.name ?? (typed.isEmpty ? "Group" : typed)
        SavedGroups.switchTo(groupName: n, code: clean, engine: engine, pins: InviteLinks.pins(invited, for: clean))
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        Nav.shared.toast("You're now in \(n)")
        Nav.shared.sheet = nil
        dismiss()
    }
}

/// A new group with a fresh random code: asks for a name (optional), then opens the invite.
struct CreateGroupSheet: View {
    @ObservedObject var engine: Engine
    @Environment(\.dismiss) private var dismiss
    @AppStorage("name") private var myName = ""
    @State private var name = ""
    @State private var code = Invite.newCode()

    var body: some View {
        SheetPage(title: "Create a group", close: "Cancel") {
            Text("GoDark makes a new secret code for it. Then you invite people with a QR code. Your other groups stay saved.")
                .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
            InputField(label: "Group name (optional)", hint: "You can change it later.") {
                TextField("", text: $name, prompt: Text(SavedGroups.defaultName(for: myName)).foregroundColor(Theme.faint)).submitLabel(.done)
            }
            if let drop = SavedGroups.wouldDrop(for: code) {
                Text("You have \(SavedGroups.max) groups saved. A new one removes the oldest, \(drop.name), from this phone.")
                    .scaledFont(14).foregroundStyle(Theme.help).fixedSize(horizontal: false, vertical: true)
            }
            Button("Create group") { create() }.buttonStyle(PrimaryButton())
        }
    }

    private func create() {
        let typed = String(name.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Invite.maxGroupName))
        Engine.found(code) // its first epoch is made on this phone (v0.6)
        SavedGroups.switchTo(groupName: typed.isEmpty ? SavedGroups.defaultName(for: myName) : typed, code: code, engine: engine)
        UINotificationFeedbackGenerator().notificationOccurred(.success)
        Nav.shared.sheet = nil
        dismiss()
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) { Nav.shared.sheet = .invite } // invite people to it
    }
}

// MARK: - Group list

/// Every saved group, with unread messages and anyone needing help, to switch with one tap; join or create below.
struct GroupsCard: View {
    @ObservedObject var engine: Engine
    @ObservedObject private var unread = Unread.shared
    @CurrentCode private var code
    @AppStorage("groupName") private var groupName = "My group"
    @State private var joining = false
    @State private var creating = false

    var body: some View {
        let others = SavedGroups.all().filter { $0.code != code }
        Card {
            Text("Your groups").scaledFont(17, .bold).foregroundStyle(Theme.text)
            row(groupName, code: code, current: true)
            ForEach(others) { g in row(g.name, code: g.code, current: false) }
            if others.isEmpty {
                Text("Groups you switch away from stay here, so you can come back.").scaledFont(14).foregroundStyle(Theme.dim)
            }
            HStack(spacing: 10) {
                Button { joining = true } label: { Label("Join", systemImage: "qrcode.viewfinder") }.buttonStyle(GhostButton())
                Button { creating = true } label: { Label("Create", systemImage: "plus") }.buttonStyle(GhostButton())
            }
            Text("Messages of every saved group arrive and alert you, whichever one is on screen.")
                .font(.footnote).foregroundStyle(Theme.dim)
        }
        .sheet(isPresented: $joining) { JoinGroupSheet(engine: engine) }
        .sheet(isPresented: $creating) { CreateGroupSheet(engine: engine) }
    }

    private func row(_ name: String, code c: String, current: Bool) -> some View {
        let msgs = engine.allMessages.filter { !$0.isPublic && $0.group == c }
        let n = unread.count(c, in: engine.allMessages, me: engine.deviceId)
        let help = Person.all(in: msgs, me: engine.deviceId).filter { $0.checkIn == .help }.count
        return HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(name).scaledFont(17, .semibold).foregroundStyle(Theme.text).lineLimit(1)
                HStack(spacing: 6) {
                    if help > 0 { Chip(help == 1 ? "1 needs help" : "\(help) need help", Theme.help) }
                    if n > 0 { Chip("\(n) new") }
                }
            }
            Spacer()
            if current { Chip("On screen", Theme.safe) }
            else { Button("Switch") { switchTo(name, c) }.buttonStyle(GhostButton()).accessibilityLabel("Switch to \(name)") }
        }
        .accessibilityElement(children: .combine)
    }

    private func switchTo(_ name: String, _ c: String) {
        SavedGroups.switchTo(groupName: name, code: c, engine: engine)
        Nav.shared.toast("You're now in \(name)")
        Nav.shared.sheet = nil
    }
}

/// Opened from the group name on Home: switch, join or create.
struct GroupSwitcher: View {
    @ObservedObject var engine: Engine
    var body: some View {
        SheetPage(title: "Groups") { GroupsCard(engine: engine) }
    }
}
