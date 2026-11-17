// swift-tools-version: 6.0
// Platform-independent core of the iPhone app: packet format, group encryption, and forwarding.
// Same behavior and bytes as the Android app's Core.kt; see spec/FORMAT.md.
import PackageDescription

let package = Package(
    name: "BlackoutCore",
    platforms: [.iOS("26.0"), .macOS("26.0")], // CryptoKit has ML-KEM from 26: every phone in a group needs it
    products: [.library(name: "BlackoutCore", targets: ["BlackoutCore"])],
    targets: [
        // Always optimized, also in Debug builds: unoptimized, the group-key step takes seconds instead of milliseconds.
        .target(name: "Scrypt", swiftSettings: [.unsafeFlags(["-O"])]),
        .target(name: "BlackoutCore", dependencies: ["Scrypt"]),
        .testTarget(name: "BlackoutCoreTests", dependencies: ["BlackoutCore", "Scrypt"]),
    ]
)
