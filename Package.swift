// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let tag = "v0.7.0"
let checksum = "5f9bd7c756420a0a181ece87fc8ce6f450c0731eae62ad5753e59c4c736f457b"
let url = "https://github.com/lightningdevkit/ldk-node/releases/download/\(tag)/LDKNodeFFI.xcframework.zip"

let package = Package(
    name: "ldk-node",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "LDKNode",
            targets: ["LDKNodeFFI", "LDKNode"]),
    ],
    targets: [
        .target(
            name: "LDKNode",
            dependencies: ["LDKNodeFFI"],
            path: "./bindings/swift/Sources"
        ),
        .binaryTarget(
            name: "LDKNodeFFI",
            url: url,
            checksum: checksum
            )
    ]
)
