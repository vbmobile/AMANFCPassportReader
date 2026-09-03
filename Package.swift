// swift-tools-version:5.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "AMANFCPassportReader",
    platforms: [.iOS("15.0")],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "AMANFCPassportReader",
            targets: ["AMANFCPassportReader"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/krzyzanowskim/OpenSSL-Package.git", .upToNextMinor(from: "3.6.0001")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        // The source directories keep the upstream names so merges from AndyQ/NFCPassportReader stay path-clean.
        .target(
            name: "AMANFCPassportReader",
            dependencies: [
              .product(name: "OpenSSL", package: "OpenSSL-Package")
            ],
            path: "Sources/NFCPassportReader"),
        .testTarget(
            name: "AMANFCPassportReaderTests",
            dependencies: [
              "AMANFCPassportReader",
              .product(name: "OpenSSL", package: "OpenSSL-Package")
            ],
            path: "Tests/NFCPassportReaderTests"),
    ]
)
