// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "swift-murmur3",
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
