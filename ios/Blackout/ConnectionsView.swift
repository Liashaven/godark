import SwiftUI
import CoreBluetooth
import BlackoutCore

/// Home's "Connect" tile: the same lines as Settings > Advanced, without blocked people.
struct ConnectionsView: View {
    @ObservedObject var engine: Engine

    var body: some View {
        SheetPage(title: "Connections") {
            Text("The ways your messages travel. All but Internet keep working in a blackout.")
                .scaledFont(15).foregroundStyle(Theme.dim)
            SetupProblemCard(engine: engine)
            AdvancedRows(engine: engine, showBlocked: false)
        }
    }

    /// This iPhone's address on its Wi-Fi network (or its hotspot), for people who type it on another phone.
    static func localAddress() -> String? {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let i = p.pointee
            guard let sa = i.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) else { continue }
            let name = String(cString: i.ifa_name)
            guard name.hasPrefix("en") || name.hasPrefix("bridge") else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(sa, socklen_t(sa.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                return String(cString: host)
            }
        }
        return nil
    }
}

/// Settings > Advanced: every way messages travel, the battery saver and blocked people, one line each.
/// Plain on/off switches right here (the switch tells the engine at once, from any page); the rest open a page.
struct AdvancedRows: View {
    @ObservedObject var engine: Engine
    var showBlocked = true
    @ObservedObject private var battery = BatteryMonitor.shared
    @AppStorage("wifiNetwork") private var wifiOn = true
    @AppStorage("internet") private var internetOn = true
    @AppStorage("tor") private var torOn = true
    @AppStorage("saver") private var saverOn = false
    @State private var blocked = 0

    var body: some View {
        RowCard {
            LinkRow(icon: "dot.radiowaves.left.and.right", title: "Nearby phones",
                    value: engine.phones > 0 ? "\(engine.phones) linked" : "Searching") { NearbyPage(engine: engine) }
            SwitchRow(icon: "wifi", title: "Wi-Fi network", detail: wifiDetail.text, detailColor: wifiDetail.color,
                      isOn: Binding(get: { wifiOn }, set: { wifiOn = $0; engine.setWifi($0) }))
            SwitchRow(icon: "globe", title: "Internet", detail: internetDetail.text, detailColor: internetDetail.color,
                      isOn: Binding(get: { internetOn }, set: { internetOn = $0; engine.setInternet($0) }))
            if internetOn {
                SwitchRow(icon: "lock.shield.fill", title: "Through Tor",
                          detail: "Hides your internet address from the relays. Slower, uses more battery.",
                          isOn: Binding(get: { torOn }, set: { torOn = $0; engine.setTor($0) }))
            }
            LinkRow(icon: "antenna.radiowaves.left.and.right", title: "Long-range radio", value: radioValue) { RadioPage(engine: engine) }
            SwitchRow(icon: "battery.50percent", title: "Battery saver", detail: saverDetail,
                      isOn: Binding(get: { saverOn }, set: { saverOn = $0; engine.setSaver($0) }))
            LinkRow(icon: "square.and.arrow.up", title: "Send through another app") { ShareStatusPage(engine: engine) }
            if showBlocked {
                LinkRow(icon: "nosign", title: "Blocked people", value: blocked == 0 ? "None" : "\(blocked)") { BlockedPage(engine: engine) }
            }
        }
        .onAppear { blocked = Moderation.blocked.count }
    }

    private var wifiDetail: (text: String, color: Color) {
        if !wifiOn { return ("Off", Theme.dim) }
        if saverOn { return ("Paused by Battery saver", Theme.dim) }
        if engine.localNetworkDenied { return ("Not allowed: turn on Local Network for GoDark in iPhone Settings", Theme.help) }
        let n = engine.wifiNetworkLinks
        return n > 0 ? ("\(n) phone\(n == 1 ? "" : "s") linked", Theme.safe) : ("Finds phones on the same Wi-Fi, even with no internet", Theme.dim)
    }

    private var internetDetail: (text: String, color: Color) {
        if !internetOn { return ("Off: messages go only from phone to phone", Theme.dim) }
        if engine.torSlow { return ("Tor can't connect right now. Nearby phones still work.", Theme.help) }
        if engine.throughTor == false { return ("Starting Tor… the first time can take a minute", Theme.dim) }
        return engine.relaysLinked > 0 ? ("Online" + (engine.throughTor == true ? " through Tor" : "") + ": reaches friends far away", Theme.safe)
                                       : ("No internet right now", Theme.dim)
    }

    private var radioValue: String {
        if engine.radioLinked || engine.meshcoreLinked { return "Linked" }
        return engine.lora.hasRadio || engine.meshcore.hasRadio ? "Paired" : "None"
    }

    private var saverDetail: String {
        if let h = battery.hoursLeft { return "Battery: \(BatteryMonitor.text(h)) at this pace" }
        return "Looks for phones less often, so the battery lasts longer"
    }
}

/// Settings > Advanced > Nearby phones: what is linked, and a Wi-Fi address to dial by hand.
struct NearbyPage: View {
    @ObservedObject var engine: Engine
    @AppStorage("wifiNetwork") private var wifiOn = true
    @AppStorage("saver") private var saverOn = false
    @State private var address = ""

    var body: some View {
        SettingsPage(title: "Nearby phones") {
            SetupProblemCard(engine: engine)
            Card {
                HStack {
                    Text("Bluetooth").scaledFont(17, .bold).foregroundStyle(Theme.text)
                    Spacer()
                    Chip(engine.phones > 0 ? "\(engine.phones) linked" : "Searching", engine.phones > 0 ? Theme.safe : Theme.dim)
                }
                Text("iPhones and Android phones with GoDark within about 10–50 m connect by themselves.")
                    .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(engine.friendlyStatus.prefix(2), id: \.self) { Text($0).scaledFont(14).foregroundStyle(Theme.dim) }
                }
            }
            Card {
                Text("Same Wi-Fi network").scaledFont(17, .bold).foregroundStyle(Theme.text)
                Text("Phones on the same Wi-Fi find each other: a router with no internet, a phone hotspot, a neighbourhood network or a long-range rooftop link.")
                    .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                if !wifiOn {
                    Text("Wi-Fi network is off in Settings.").scaledFont(15, .semibold).foregroundStyle(Theme.dim)
                } else if saverOn {
                    Text("Paused by Battery saver.").scaledFont(15, .semibold).foregroundStyle(Theme.dim)
                } else {
                    let n = engine.wifiNetworkLinks
                    if engine.localNetworkDenied {
                        Text("Local Network is not allowed for GoDark.").scaledFont(15, .semibold).foregroundStyle(Theme.help)
                        OpenSettingsButton()
                    } else {
                        Text(n > 0 ? "\(n) phone\(n == 1 ? "" : "s") linked over Wi-Fi" : "Looking on this network")
                            .scaledFont(15, .semibold).foregroundStyle(n > 0 ? Theme.safe : Theme.dim)
                    }
                    if let ip = ConnectionsView.localAddress(), let port = engine.wifi.listeningPort {
                        Text("This iPhone: \(ip):\(String(port))").scaledFont(14).foregroundStyle(Theme.dim).textSelection(.enabled)
                    }
                    InputField(label: "Connect to an address") {
                        TextField("", text: $address, prompt: Text("192.168.1.20:7777").foregroundColor(Theme.faint))
                            .keyboardType(.numbersAndPunctuation).textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    HStack(spacing: 10) {
                        Button("Connect") { connect() }.buttonStyle(GhostButton())
                        if engine.wifi.manualAddress != nil { Button("Stop") { engine.wifi.stopManual() }.buttonStyle(GhostButton()) }
                    }
                    Text("Only needed when phones don't find each other on their own, for example on networks that block it.")
                        .scaledFont(14).foregroundStyle(Theme.faint).fixedSize(horizontal: false, vertical: true)
                    if let line = engine.status["4-wifi"], line.contains("retrying") || line.contains("can't") {
                        Text(line.replacingOccurrences(of: "Wi-Fi network: ", with: "")).scaledFont(14).foregroundStyle(Theme.dim)
                    }
                }
            }
        }
        .onAppear { address = engine.wifi.manualAddress ?? "" }
    }

    private func connect() {
        let a = address.trimmingCharacters(in: .whitespaces)
        if let i = a.lastIndex(of: ":"), i > a.startIndex, let port = UInt16(a[a.index(after: i)...]) {
            engine.wifi.connect(host: String(a[..<i]), port: port)
            Nav.shared.toast("Connecting to \(a)")
        } else {
            Nav.shared.toast("Type an address like 192.168.1.20:7777")
        }
    }
}

/// Settings > Advanced > Long-range radio: pair a Meshtastic or MeshCore LoRa radio.
struct RadioPage: View {
    @ObservedObject var engine: Engine

    var body: some View {
        SettingsPage(title: "Long-range radio") {
            Text("A LoRa radio paired with this iPhone reaches other radios kilometers away, with no network at all. Short messages only.")
                .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
            RadioCard(engine: engine, kind: .meshtastic)
            RadioCard(engine: engine, kind: .meshcore)
        }
    }
}

/// Settings > Advanced > Send through another app: a check-in as plain text, for satellite messengers or SMS.
struct ShareStatusPage: View {
    @ObservedObject var engine: Engine
    @State private var share: ShareText?
    @State private var preparing: CheckIn?

    struct ShareText: Identifiable { let id = UUID(); let text: String }

    var body: some View {
        SettingsPage(title: "Send through another app") {
            Card {
                Text("For satellite messengers such as Garmin inReach or Zoleo, text messages once the network is back, or any app. It includes your battery and, if location is on, where you are. It leaves GoDark: that app decides who can read it.")
                    .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
                if preparing != nil {
                    Label("Getting your position…", systemImage: "location.fill").scaledFont(15, .semibold).foregroundStyle(Theme.text)
                }
                HStack(spacing: 10) {
                    Button("Share “I'm safe”") { shareStatus(.safe) }.buttonStyle(GhostButton())
                    Button("Share “I need help”") { shareStatus(.help) }.buttonStyle(GhostButton())
                }
                .disabled(preparing != nil)
            }
        }
        .sheet(item: $share) { s in ActivityView(items: [s.text]).ignoresSafeArea() }
    }

    /// Shares a check-in as plain text through another app (StatusShare), with battery and position when available.
    /// Getting a fix can take up to 10 s: the buttons wait meanwhile.
    private func shareStatus(_ c: CheckIn) {
        guard preparing == nil else { return }
        preparing = c
        let battery = Engine.batteryPercent, name = engine.name
        LocationService.shared.fix { spot in
            preparing = nil
            share = ShareText(text: StatusShare.text(c, name: name, battery: battery, spot: spot))
        }
    }
}

/// Settings > Advanced > Blocked people.
struct BlockedPage: View {
    @ObservedObject var engine: Engine
    @State private var blocked: [String: String] = [:]

    var body: some View {
        SettingsPage(title: "Blocked people") {
            Text("Their messages, places and check-ins are hidden on this phone. In Everyone, hold a message to block its sender.")
                .scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
            if blocked.isEmpty {
                Card { Text("No one is blocked.").scaledFont(17, .semibold).foregroundStyle(Theme.text) }
            } else {
                Card {
                    ForEach(blocked.sorted(by: { $0.value < $1.value }), id: \.key) { id, name in
                        HStack {
                            Text(name).scaledFont(17, .semibold).foregroundStyle(Theme.text)
                            Spacer()
                            Button("Unblock") { Moderation.unblock(id); blocked = Moderation.blocked; engine.moderationChanged() }
                                .buttonStyle(GhostButton()).accessibilityLabel("Unblock \(name)")
                        }
                    }
                }
            }
        }
        .onAppear { blocked = Moderation.blocked }
    }
}

/// The system share sheet, for "Send via another app".
struct ActivityView: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController { UIActivityViewController(activityItems: items, applicationActivities: nil) }
    func updateUIViewController(_ vc: UIActivityViewController, context: Context) {}
}

/// Search, pair and forget one kind of LoRa radio (Meshtastic or MeshCore).
struct RadioCard: View {
    struct Radio: Identifiable { let id: UUID; let name: String }
    enum Kind { case meshtastic, meshcore }
    @ObservedObject var engine: Engine
    var kind = Kind.meshtastic
    @State private var radios: [Radio] = []
    @State private var searching = false
    @State private var searchId = 0
    @State private var note = ""
    @State private var confirmForget = false

    private var title: String { kind == .meshtastic ? "LoRa radio · Meshtastic" : "LoRa radio · MeshCore" }
    private var about: String {
        kind == .meshtastic
            ? "Reaches other radios kilometers away: about 2–10 km in a city, more from high places. Short messages only. Use a Meshtastic radio with the region set (EU_868 in Europe)."
            : "The same kind of radio with MeshCore firmware, version 1.15 or newer. GoDark adds a #darkproof channel to the radio and every MeshCore repeater passes it on. Short messages only. The radio's PIN is often 123456 or shown on its screen."
    }
    private var linked: Bool { kind == .meshtastic ? engine.radioLinked : engine.meshcoreLinked }
    private var paired: Bool { kind == .meshtastic ? engine.lora.hasRadio : engine.meshcore.hasRadio }
    private var statusText: String {
        let key = kind == .meshtastic ? "3-lora" : "3b-meshcore", prefix = kind == .meshtastic ? "LoRa: " : "MeshCore: "
        let s = (engine.status[key] ?? prefix + "no radio").replacingOccurrences(of: prefix, with: "")
        return s.prefix(1).uppercased() + s.dropFirst()
    }

    var body: some View {
        Card {
            HStack {
                Text(title).scaledFont(20, .bold).foregroundStyle(Theme.text)
                Spacer()
                Chip(linked ? "Linked" : "Not linked", linked ? Theme.safe : Theme.dim)
            }
            Text(about).scaledFont(15).foregroundStyle(Theme.dim).fixedSize(horizontal: false, vertical: true)
            Text(statusText).scaledFont(14, .semibold).foregroundStyle(linked ? Theme.safe : Theme.text)
            HStack(spacing: 10) {
                Button(searching ? "Searching…" : radios.isEmpty ? "Search for radios" : "Search again") { search() }
                    .buttonStyle(GhostButton()).disabled(searching)
                if paired { Button("Forget radio") { confirmForget = true }.buttonStyle(GhostButton()) }
            }
            if searching && radios.isEmpty {
                Text("Looking for radios nearby… Turn the radio on and keep it next to the phone.")
                    .font(.footnote).foregroundStyle(Theme.dim)
            }
            ForEach(radios) { r in
                HStack(spacing: 12) {
                    Text(r.name).scaledFont(16, .semibold).foregroundStyle(Theme.text)
                    Spacer()
                    Button("Connect") {
                        if kind == .meshtastic { engine.lora.select(r.id) } else { engine.meshcore.select(r.id) }
                        note = "Connecting. If asked, enter the PIN shown on the radio."
                    }
                    .buttonStyle(GhostButton())
                }
            }
            if !note.isEmpty { Text(note).font(.footnote).foregroundStyle(Theme.dim) }
        }
        .confirmationDialog("Forget this radio?", isPresented: $confirmForget, titleVisibility: .visible) {
            Button("Forget radio", role: .destructive) {
                if kind == .meshtastic { engine.lora.forget() } else { engine.meshcore.forget() }
                radios = []; note = ""
                Nav.shared.toast("Radio forgotten")
            }
            Button("Keep it", role: .cancel) {}
        } message: {
            Text("GoDark disconnects and stops connecting to it. To pair it again, search for radios.")
        }
    }

    /// Lists radios for 15 s (the links scan that long), then says if none answered.
    private func search() {
        switch engine.bluetooth {
        case .poweredOff: note = "Bluetooth is off. Turn it on in Control Center, then search again."; return
        case .unauthorized: note = "GoDark may not use Bluetooth. Allow it in Settings, then search again."; return
        case .unsupported: note = "This device has no Bluetooth."; return
        default: break
        }
        radios = []; searching = true; note = ""
        searchId += 1
        let id = searchId
        let found: (UUID, String) -> Void = { rid, name in
            if !radios.contains(where: { $0.id == rid }) { radios.append(Radio(id: rid, name: name)) }
        }
        if kind == .meshtastic { engine.lora.scan(found: found) } else { engine.meshcore.scan(found: found) }
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) {
            guard id == searchId else { return }
            searching = false
            if radios.isEmpty { note = "No radios found. Turn the radio on, keep it next to the phone and search again." }
        }
    }
}
