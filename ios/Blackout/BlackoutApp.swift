import SwiftUI
import BlackoutCore

@main
struct BlackoutApp: App {
    init() {
        Vault.wipeAfterReinstall() // before anything reads the Keychain
        OfflineMap.shared.setUp()
        Notifier.shared.setUp() // before launch ends, so tapping an alert that relaunched the app is handled
        #if DEBUG
        let args = CommandLine.arguments // devicectl ... launch --console it.darkproof.mesh aiSelfTest <model file>
        if let i = args.firstIndex(of: "join"), args.indices.contains(i + 1), let bar = args[i + 1].firstIndex(of: "|") {
            // join "Name|code": the test group, like Android's --es join (group codes never go in logs)
            UserDefaults.standard.set(String(args[i + 1][..<bar]), forKey: "name")
            GroupSecrets.shared.setCode(String(args[i + 1][args[i + 1].index(after: bar)...]))
        }
        if let i = args.firstIndex(of: "joinLink"), args.indices.contains(i + 1), let bar = args[i + 1].firstIndex(of: "|"),
           let invite = InviteLinks.read(String(args[i + 1][args[i + 1].index(after: bar)...])) { // joinLink "Name|darkproof://join?…": like join, through the code that reads an invite
            UserDefaults.standard.set(String(args[i + 1][..<bar]), forKey: "name")
            GroupSecrets.shared.joining(invite.code, pins: invite.pins)
            GroupSecrets.shared.setCode(invite.code)
        }
        if args.contains("found"), let c = GroupSecrets.shared.current { Engine.found(c) } // with join: as if this phone created the group
        if let i = args.firstIndex(of: "ahead"), args.indices.contains(i + 1), let days = Int64(args[i + 1]) { Engine.ahead = days * 86_400_000 } // ahead 8
        for i in args.indices where args[i] == "set" && args.indices.contains(i + 2) { // set wifiNetwork 0 (repeatable)
            UserDefaults.standard.set(args[i + 2] == "1", forKey: args[i + 1])
        }
        if let i = args.firstIndex(of: "relays"), args.indices.contains(i + 1) { // relays ws://127.0.0.1:7447: tools/mock-relay
            NostrLink.debugRelays = args[i + 1].split(separator: ",").map(String.init)
        }
        #endif
        Mesh.shared.startIfSetUp() // also when iOS relaunches the app in the background for Bluetooth
        #if DEBUG
        if args.contains("dumpChat") { // for the mock-relay tests: what this phone shows, every 3 s (never the group code)
            Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { _ in
                guard let e = Mesh.shared.engine else { return }
                DebugLog.write("CHAT " + e.messages.map { "\($0.id):\($0.verified ? "v" : "u"):\($0.name):\($0.text.prefix(60))" }.joined(separator: " | "))
            }
        }
        if let i = args.firstIndex(of: "aiSelfTest") { LocalAi.selfTest(args.indices.contains(i + 1) ? args[i + 1] : nil) }
        if let i = args.firstIndex(of: "interopTest"), args.indices.contains(i + 1) { InteropTest.run(args[i + 1]) }
        if let i = args.firstIndex(of: "unlockAfter"), args.indices.contains(i + 1), let s = Double(args[i + 1]) { // unlockAfter 10
            DispatchQueue.main.asyncAfter(deadline: .now() + s) { AppLock.shared.unlockForTests() }
        }
        if args.contains("logPins") { // key hashes, not the group code
            DispatchQueue.main.asyncAfter(deadline: .now() + 6) { DebugLog.write("pins " + (GroupSecrets.shared.current.flatMap { Mesh.shared.engine?.invitePins($0) } ?? "none")) }
        }
        if args.contains("samples") { InteropTest.samples(after: 8) } // no link: the messages go by whatever is up, e.g. relays
        if let i = args.firstIndex(of: "say"), args.indices.contains(i + 1) { // say Hello: to the group on screen only
            DispatchQueue.main.asyncAfter(deadline: .now() + 12) { Mesh.shared.engine?.send(args[i + 1]); DebugLog.write("said") }
        }
        if let i = args.firstIndex(of: "approve"), args.indices.contains(i + 1) { // approve Bea: lets them in, by name
            DispatchQueue.main.asyncAfter(deadline: .now() + 12) {
                guard let e = Mesh.shared.engine, let r = e.joinRequests(GroupSecrets.shared.current).first(where: { $0.name == args[i + 1] }) else { DebugLog.write("approve: nobody with that name is asking"); return }
                e.approveJoin(GroupSecrets.shared.current, r.id) { DebugLog.write("approve \(args[i + 1]): \($0)") }
            }
        }
        for (arg, change) in [("makeAdmin", Engine.makeAdmin), ("removeMember", Engine.remove)] as [(String, (Engine) -> (String?, String, @escaping (Bool) -> Void) -> Void)] {
            guard let i = args.firstIndex(of: arg), args.indices.contains(i + 1) else { continue } // makeAdmin Ben, removeMember Marco: by name
            DispatchQueue.main.asyncAfter(deadline: .now() + 12) {
                guard let e = Mesh.shared.engine, let p = Person.all(in: e.messages, me: e.deviceId).first(where: { $0.name == args[i + 1] }) else { DebugLog.write("\(arg): nobody with that name"); return }
                change(e)(GroupSecrets.shared.current, p.id) { DebugLog.write("\(arg) \(args[i + 1]): \($0)") }
            }
        }
        #endif
    }

    var body: some Scene {
        WindowGroup { RootView().preferredColorScheme(.dark) }
    }
}

#if DEBUG
/// Debug builds only: `simctl launch booted it.darkproof.mesh interopTest 127.0.0.1:7777` links to the Android app's
/// LAN test listener, then sends a check-in with battery and position, a place and a small photo, for the mixed-group test.
enum InteropTest {
    static func run(_ address: String) {
        guard let i = address.lastIndex(of: ":"), let port = UInt16(address[address.index(after: i)...]) else { return }
        let host = String(address[..<i])
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            guard let e = Mesh.shared.engine else { DebugLog.write("interop: no group"); return }
            e.wifi.connect(host: host, port: port)
            samples(after: 4)
        }
    }

    static func samples(after delay: Double) {
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            guard let e = Mesh.shared.engine else { DebugLog.write("interop: no group"); return }
            let spot = Spot(lat: 45.46420, lon: 9.19000, accuracy: 12)
            e.send(CheckIn.safe.text(battery: 64, spot: spot))
            e.send(Place(kind: .water, note: "Fountain in the square", spot: spot).text, isPublic: true)
            let img = UIGraphicsImageRenderer(size: CGSize(width: 320, height: 240)).image { c in
                UIColor.systemTeal.setFill(); c.fill(CGRect(x: 0, y: 0, width: 320, height: 240))
                UIColor.white.setFill(); c.fill(CGRect(x: 100, y: 60, width: 120, height: 120))
            }
            if let jpeg = PhotoShrinker.jpeg(img) { e.send(Photo.text(caption: "From the iPhone"), photo: jpeg) }
            e.send("Hello from the iPhone")
            DebugLog.write("interop: sent check-in, place, photo, text")
        }
    }
}
#endif
