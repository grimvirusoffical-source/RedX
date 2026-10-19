// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "RedX",
    platforms: [.macOS(.v12), .iOS(.v15), .tvOS(.v15)],
    products: [.library(name: "RedX", targets: ["RedX"])],
    targets: [
        .target(name: "RedX", path: "Sources/RedX"),
        .testTarget(name: "RedXTests", dependencies: ["RedX"], path: "Tests/RedXTests"),
    ]
)
