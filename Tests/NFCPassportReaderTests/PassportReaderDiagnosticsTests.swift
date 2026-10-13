//
//  PassportReaderDiagnosticsTests.swift
//

import Foundation
import OSLog
import XCTest

@testable import NFCPassportReader

/// Hosts collect the reader's milestones from a notification because a tester's
/// build cannot read the unified log. Debug events must never reach it: they
/// carry the access key, session keys and APDU contents.
final class PassportReaderDiagnosticsTests: XCTestCase {
    func testInformationalEventsArePosted() {
        let messages = collect { Logger.session.info("probe milestone") }

        XCTAssertTrue(messages.contains { $0.contains("probe milestone") && $0.contains("[session]") })
    }

    func testErrorsArePosted() {
        let messages = collect { Logger.passportReader.error("probe failure") }

        XCTAssertTrue(messages.contains { $0.contains("probe failure") })
    }

    func testDebugEventsStayOffTheChannel() {
        let messages = collect { Logger.bac.debug("probe secret") }

        XCTAssertFalse(messages.contains { $0.contains("probe secret") })
    }

    func testSessionEndReasonsNameTheCause() {
        XCTAssertEqual(PassportReader.sessionEndReason(for: .ConnectionError), "tag connection lost")
        XCTAssertEqual(PassportReader.sessionEndReason(for: .TimeOutError), "session timeout")
        XCTAssertEqual(PassportReader.sessionEndReason(for: .UserCanceled), "user cancelled")
        XCTAssertTrue(PassportReader.sessionEndReason(for: .UnknownImageFormat).hasPrefix("error - "))
    }

    func testSystemErrorsAreDescribedByDomainCodeAndUnderlyingError() {
        let underlying = NSError(domain: "ProbeTransport", code: 7)
        let error = NSError(
            domain: "ProbeSession",
            code: 42,
            userInfo: [NSLocalizedDescriptionKey: "probe failed", NSUnderlyingErrorKey: underlying]
        )

        XCTAssertEqual(diagnosticDescription(of: error), "ProbeSession 42: probe failed (underlying ProbeTransport 7)")
        XCTAssertEqual(diagnosticDescription(of: NFCPassportReaderError.TimeOutError), "\(NFCPassportReaderError.TimeOutError)")
    }

    func testDomainParameterIdentifiersAreNamed() {
        XCTAssertEqual(PACEInfo.domainParameterName(13), "brainpoolP256r1")
        XCTAssertEqual(PACEInfo.domainParameterName(12), "NIST P-256")
        XCTAssertEqual(PACEInfo.domainParameterName(nil), "not specified")
        XCTAssertEqual(PACEInfo.domainParameterName(99), "unsupported")
    }
}

// MARK: - Private
private extension PassportReaderDiagnosticsTests {
    func collect(_ body: () -> Void) -> [String] {
        var messages: [String] = []
        let observer = NotificationCenter.default.addObserver(
            forName: PassportReaderDiagnostics.notificationName,
            object: nil,
            queue: nil
        ) { notification in
            if let message = notification.userInfo?["message"] as? String {
                messages.append(message)
            }
        }
        defer { NotificationCenter.default.removeObserver(observer) }
        body()
        return messages
    }
}
