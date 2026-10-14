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
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        // The source directories keep the upstream names so merges from AndyQ/NFCPassportReader stay path-clean.
        .target(
            name: "AMANFCPassportReader",
            dependencies: [
              "OpenSSL"
            ],
            path: "Sources/NFCPassportReader"),
        .testTarget(
            name: "AMANFCPassportReaderTests",
            dependencies: [
              "AMANFCPassportReader",
              "OpenSSL"
            ],
            path: "Tests/NFCPassportReaderTests"),
        // OpenSSL-Package 3.6.5000's XCFramework, re-hosted unchanged: GitHub release-asset downloads stall past SwiftPM's timeout on the corporate network.
        .binaryTarget(
            name: "OpenSSL",
            url: "https://vbmobileidstorage.blob.core.windows.net/ios/OpenSSL/OpenSSL-3.6.5000.xcframework.zip",
            checksum: "f50188506490c643715489217d32e458d06cee5579399ff616f0ce2038169fea"
        ),
    ]
)
