//
//  Logging.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

/// The reader's diagnostic channel for hosts that cannot read the unified log,
/// such as a tester's build that collects and shares its own logs.
///
/// Every info, notice, warning, error and fault event the reader logs is also
/// posted on `notificationName`, with the text under `"message"`, the level under
/// `"level"` and the log category under `"category"` in `userInfo`. Debug events
/// are never posted: they carry access keys, session keys and APDU contents.
public enum PassportReaderDiagnostics {
    public static let notificationName = Notification.Name("AMANFCPassportReader.log")
}

/// An error as the session log reports it: the reader's own errors by case, any other by domain
/// and code, which is what a system error such as CoreNFC's is looked up by.
func diagnosticDescription(of error: Error) -> String {
    if let readerError = error as? NFCPassportReaderError {
        return "\(readerError)"
    }
    let nsError = error as NSError
    var text = "\(nsError.domain) \(nsError.code): \(nsError.localizedDescription)"
    if let underlying = nsError.userInfo[NSUnderlyingErrorKey] as? NSError {
        text += " (underlying \(underlying.domain) \(underlying.code))"
    }
    return text
}

extension Logger {
    /// Using your bundle identifier is a great way to ensure a unique identifier.
    private static var subsystem = Bundle.main.bundleIdentifier ?? "AMANFCPassportReader"

    /// Tag Reader logs
    static let passportReader = ReaderLogger(subsystem: subsystem, category: "passportReader")

    /// Tag Reader logs
    static let tagReader = ReaderLogger(subsystem: subsystem, category: "tagReader")

    /// SecureMessaging logs
    static let secureMessaging = ReaderLogger(subsystem: subsystem, category: "secureMessaging")

    static let openSSL = ReaderLogger(subsystem: subsystem, category: "openSSL")

    static let bac = ReaderLogger(subsystem: subsystem, category: "BAC")
    static let chipAuth = ReaderLogger(subsystem: subsystem, category: "chipAuthentication")
    static let pace = ReaderLogger(subsystem: subsystem, category: "PACE")

    /// Chip session milestones: access control, data group reads and how the session ended.
    static let session = ReaderLogger(subsystem: subsystem, category: "session")

    /// One line per APDU when `PassportReader.apduTrace` is on: command, lengths, status word
    /// and timing, never the bytes carried.
    static let apdu = ReaderLogger(subsystem: subsystem, category: "apdu")
}

/// Writes to the unified log like `Logger`, and posts everything above debug on
/// `PassportReaderDiagnostics.notificationName`.
struct ReaderLogger {
    private let logger: Logger
    private let category: String

    init(subsystem: String, category: String) {
        logger = Logger(subsystem: subsystem, category: category)
        self.category = category
    }

    func debug(_ message: @escaping @autoclosure () -> String) {
        logger.debug("\(message(), privacy: .private)")
    }

    func info(_ message: @escaping @autoclosure () -> String) {
        let text = message()
        logger.info("\(text, privacy: .public)")
        post(text, level: "INFO")
    }

    func notice(_ message: @escaping @autoclosure () -> String) {
        let text = message()
        logger.notice("\(text, privacy: .public)")
        post(text, level: "NOTICE")
    }

    func warning(_ message: @escaping @autoclosure () -> String) {
        let text = message()
        logger.warning("\(text, privacy: .public)")
        post(text, level: "WARNING")
    }

    func error(_ message: @escaping @autoclosure () -> String) {
        let text = message()
        logger.error("\(text, privacy: .public)")
        post(text, level: "ERROR")
    }

    func fault(_ message: @escaping @autoclosure () -> String) {
        let text = message()
        logger.fault("\(text, privacy: .public)")
        post(text, level: "FAULT")
    }

    private func post(_ message: String, level: String) {
        NotificationCenter.default.post(
            name: PassportReaderDiagnostics.notificationName,
            object: nil,
            userInfo: ["message": "[\(category)] \(message)", "level": level, "category": category]
        )
    }
}
