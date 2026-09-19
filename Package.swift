// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "PortCleanup", platforms: [.macOS(.v13)], products: [.executable(name: "PortCleanup", targets: ["PortCleanup"])], targets: [
    .target(name: "ProcessBridge"),
    .target(name: "PortCore", dependencies: ["ProcessBridge"]),
    .executableTarget(name: "PortCleanup", dependencies: ["PortCore"]),
    .executableTarget(name: "PortCoreTests", dependencies: ["PortCore"], path: "Tests/PortCoreTests")
])
