// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "swift-murmur3",
    platforms: [
        .macOS(.v15),
        .iOS(.v18),
        .tvOS(.v18),
        .watchOS(.v11),
        .visionOS(.v2),
    ],
    products: [
        .library(
            name: "Murmur3",
            targets: ["Murmur3"]
        )
    ],
    targets: [
        .target(
            name: "Murmur3"
        ),
        .testTarget(
            name: "Murmur3Tests",
            dependencies: ["Murmur3"],
            resources: [.copy("alice29.txt")]
        ),
    ]
)
