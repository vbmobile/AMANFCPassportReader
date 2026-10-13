//
//  SimulatedChip.swift
//

import CoreNFC
import Foundation

@testable import NFCPassportReader

/// An eMRTD chip at APDU level: SELECT and READ BINARY over transparent files, in plain mode or
/// under ICAO 9303-11 secure messaging keyed like the reader. It enforces short and extended
/// length limits and answers oversize reads the way real chips do, so the reader's read loop can
/// be checked round trip by round trip.
final class SimulatedChip: APDUTransport {
    struct Exchange {
        let instruction: UInt8
        let p1: UInt8
        let offset: Int
        /// The plaintext length asked for (DO'97' under secure messaging).
        let requestedLength: Int
        let extendedLength: Bool
        let responseBytes: Int
        let status: UInt16
    }

    var files: [[UInt8]: [UInt8]]
    var historicalBytes: Data?

    /// Whether the chip takes extended Lc/Le fields at all. When it does not, an extended APDU is
    /// refused with a plain 6700 and secure messaging is aborted, as ICAO 9303-11 requires.
    var acceptsExtendedLength = false
    /// Largest response APDU (status word included) the chip builds for an extended APDU.
    var maxExtendedResponse = 65538
    /// Largest plaintext length the chip hands out per READ BINARY, whatever the APDU could carry.
    var maxReadLength = Int.max
    /// How a refused read length is answered.
    var wrongLength: (UInt8, UInt8) = (0x67, 0x00)
    /// Protected errors carry the status in DO'99'. Chips differ on the outer status word: the
    /// same error, or 9000 with only DO'99' telling.
    var protectedErrorsUseOuterSuccess = false
    /// Returns 9000 without data for every READ BINARY from this offset on.
    var emptyReadsFromOffset: Int?
    /// Whether READ BINARY takes a short file identifier in P1; refused with this status if not.
    var shortFileIdentifierRefusal: (UInt8, UInt8)?
    /// How a READ BINARY that runs past the end of the file is answered.
    var pastEndOfFile = PastEndOfFile.warning
    /// Refused read lengths are answered in plain, which ends secure messaging.
    var refusesLengthInPlain = false

    enum PastEndOfFile {
        /// The bytes up to the end with 6282, as ISO/IEC 7816-4 has it.
        case warning
        /// The bytes up to the end with 9000.
        case success
        /// No data: 6Cxx with the length left, or the given status.
        case exactLength
        case refused(UInt8, UInt8)
    }

    private(set) var exchanges: [Exchange] = []
    private(set) var secureMessagingAborted = false
    private var selected: [UInt8]?
    private var keys: (algorithm: SecureMessagingSupportedAlgorithms, ksenc: [UInt8], ksmac: [UInt8])?
    private var ssc: UInt64 = 0

    init(files: [[UInt8]: [UInt8]]) {
        self.files = files
    }

    func startSecureMessaging(
        algorithm: SecureMessagingSupportedAlgorithms,
        ksenc: [UInt8],
        ksmac: [UInt8]
    ) {
        keys = (algorithm, ksenc, ksmac)
        ssc = 0
        secureMessagingAborted = false
    }

    var readBinaryExchanges: [Exchange] { exchanges.filter { $0.instruction == 0xB0 } }

    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        let extended = apdu.expectedResponseLength > 256 || (apdu.data?.count ?? 0) > 255
        if extended && !acceptsExtendedLength {
            secureMessagingAborted = keys != nil
            return record(
                apdu,
                offset: 0,
                requested: 0,
                extended: true,
                response: [],
                sw: (0x67, 0x00)
            )
        }
        if keys != nil {
            return protectedExchange(apdu, extended: extended)
        }
        let (data, sw) = execute(
            instruction: apdu.instructionCode,
            p1: apdu.p1Parameter,
            p2: apdu.p2Parameter,
            data: [UInt8](apdu.data ?? Data()),
            length: apdu.expectedResponseLength
        )
        let start = offset(apdu.p1Parameter, apdu.p2Parameter)
        if sw == (0x90, 0x00), data.count + 2 > (extended ? maxExtendedResponse : 258) {
            return record(
                apdu,
                offset: start,
                requested: apdu.expectedResponseLength,
                extended: extended,
                response: [],
                sw: wrongLength
            )
        }
        return record(
            apdu,
            offset: start,
            requested: apdu.expectedResponseLength,
            extended: extended,
            response: data,
            sw: sw
        )
    }
}

// MARK: - Private
private extension SimulatedChip {
    func offset(_ p1: UInt8, _ p2: UInt8) -> Int {
        p1 & 0x80 != 0 ? Int(p2) : Int(p1 & 0x7F) << 8 | Int(p2)
    }

    /// `status` is what the chip meant, DO'99' under secure messaging; `sw` is the outer status word.
    func record(
        _ apdu: NFCISO7816APDU,
        offset: Int,
        requested: Int,
        extended: Bool,
        response: [UInt8],
        sw: (UInt8, UInt8),
        status: (UInt8, UInt8)? = nil
    ) -> (Data, UInt8, UInt8) {
        let meant = status ?? sw
        let exchange = Exchange(
            instruction: apdu.instructionCode,
            p1: apdu.p1Parameter,
            offset: offset,
            requestedLength: requested,
            extendedLength: extended,
            responseBytes: response.count + 2,
            status: UInt16(meant.0) << 8 | UInt16(meant.1)
        )
        exchanges.append(exchange)
        return (Data(response), sw.0, sw.1)
    }

    func execute(instruction: UInt8, p1: UInt8, p2: UInt8, data: [UInt8], length: Int) -> (
        [UInt8],
        (UInt8, UInt8)
    ) {
        switch instruction {
        case 0xA4:
            if p1 == 0x04 || data == [0x3F, 0x00] || data.isEmpty {
                return ([], (0x90, 0x00))
            }
            guard files[data] != nil else { return ([], (0x6A, 0x82)) }
            selected = data
            return ([], (0x90, 0x00))
        case 0xB0:
            if p1 & 0x80 != 0 {
                if let refusal = shortFileIdentifierRefusal {
                    return ([], refusal)
                }
                guard let fileId = files.keys.first(where: { $0.count == 2 && $0[1] & 0x1F == p1 & 0x1F }) else {
                    return ([], (0x6A, 0x82))
                }
                selected = fileId
            }
            guard let fileId = selected, let file = files[fileId] else { return ([], (0x69, 0x86)) }
            let start = offset(p1, p2)
            if let emptyFrom = emptyReadsFromOffset, start >= emptyFrom {
                return ([], (0x90, 0x00))
            }
            guard start < file.count else { return ([], (0x6B, 0x00)) }
            if length > maxReadLength {
                return ([], wrongLength)
            }
            let end = min(file.count, start + length)
            guard end - start < length else {
                return ([UInt8](file[start ..< end]), (0x90, 0x00))
            }
            switch pastEndOfFile {
            case .warning:
                return ([UInt8](file[start ..< end]), (0x62, 0x82))
            case .success:
                return ([UInt8](file[start ..< end]), (0x90, 0x00))
            case .exactLength:
                return ([], (0x6C, UInt8(end - start)))
            case let .refused(sw1, sw2):
                return ([], (sw1, sw2))
            }
        default:
            return ([], (0x6D, 0x00))
        }
    }

    func protectedExchange(_ apdu: NFCISO7816APDU, extended: Bool) -> (Data, UInt8, UInt8) {
        guard let keys, !secureMessagingAborted, apdu.instructionClass == 0x0C else {
            return record(
                apdu,
                offset: 0,
                requested: 0,
                extended: extended,
                response: [],
                sw: (0x69, 0x87)
            )
        }
        let objects = Self.dataObjects([UInt8](apdu.data ?? Data()))
        let do87 = objects.first { $0.tag == 0x87 }
        let do97 = objects.first { $0.tag == 0x97 }
        guard let do8e = objects.first(where: { $0.tag == 0x8E }) else {
            secureMessagingAborted = true
            return record(
                apdu,
                offset: 0,
                requested: 0,
                extended: extended,
                response: [],
                sw: (0x69, 0x87)
            )
        }

        ssc += 1
        let header = pad(
            [0x0C, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter],
            blockSize: blockSize
        )
        let macInput = paddedSSC() + header + (do87?.encoded ?? []) + (do97?.encoded ?? [])
        let expectedMAC = mac(
            algoName: keys.algorithm,
            key: keys.ksmac,
            msg: pad(macInput, blockSize: blockSize)
        )
        guard [UInt8](expectedMAC.prefix(8)) == do8e.value else {
            secureMessagingAborted = true
            return record(
                apdu,
                offset: 0,
                requested: 0,
                extended: extended,
                response: [],
                sw: (0x69, 0x88)
            )
        }

        var commandData: [UInt8] = []
        if let do87 {
            commandData = unpad(decrypt(Array(do87.value.dropFirst())))
        }
        var length = -1
        if let le = do97?.value {
            let value = le.reduce(0) { $0 << 8 | Int($1) }
            length = value == 0 ? (le.count == 1 ? 256 : 65536) : value
        }

        let start = offset(apdu.p1Parameter, apdu.p2Parameter)
        var (data, sw) = execute(
            instruction: apdu.instructionCode,
            p1: apdu.p1Parameter,
            p2: apdu.p2Parameter,
            data: commandData,
            length: length
        )
        if refusesLengthInPlain, sw == wrongLength || sw.0 == 0x6C {
            secureMessagingAborted = true
            return record(
                apdu,
                offset: start,
                requested: length,
                extended: extended,
                response: [],
                sw: sw
            )
        }
        ssc += 1
        var response = protectedResponse(data: data, sw: sw)
        let limit = extended ? maxExtendedResponse : 258
        if response.count + 2 > limit {
            data = []
            sw = wrongLength
            response = protectedResponse(data: [], sw: sw)
        }
        let outer = sw == (0x90, 0x00) || protectedErrorsUseOuterSuccess ? (UInt8(0x90), UInt8(0x00)) : sw
        return record(
            apdu,
            offset: start,
            requested: length,
            extended: extended,
            response: response,
            sw: outer,
            status: sw
        )
    }

    func protectedResponse(data: [UInt8], sw: (UInt8, UInt8)) -> [UInt8] {
        guard let keys else { return [] }
        var do87: [UInt8] = []
        if !data.isEmpty {
            let body = [0x01] + encrypt(pad(data, blockSize: blockSize))
            do87 = [0x87] + (try! toAsn1Length(body.count)) + body
        }
        let do99: [UInt8] = [0x99, 0x02, sw.0, sw.1]
        let macInput = pad(paddedSSC() + do87 + do99, blockSize: blockSize)
        let cc = [UInt8](mac(algoName: keys.algorithm, key: keys.ksmac, msg: macInput).prefix(8))
        return do87 + do99 + [0x8E, 0x08] + cc
    }

    var blockSize: Int { keys?.algorithm == .DES ? 8 : 16 }

    func paddedSSC() -> [UInt8] {
        let counter = withUnsafeBytes(of: ssc.bigEndian, Array.init)
        return keys?.algorithm == .DES ? counter : [UInt8](repeating: 0, count: 8) + counter
    }

    func encrypt(_ message: [UInt8]) -> [UInt8] {
        guard let keys else { return [] }
        if keys.algorithm == .DES {
            return tripleDESEncrypt(
                key: keys.ksenc,
                message: message,
                iv: [UInt8](repeating: 0, count: 8)
            )
        }
        return AESEncrypt(
            key: keys.ksenc,
            message: message,
            iv: AESECBEncrypt(key: keys.ksenc, message: paddedSSC())
        )
    }

    func decrypt(_ message: [UInt8]) -> [UInt8] {
        guard let keys else { return [] }
        if keys.algorithm == .DES {
            return tripleDESDecrypt(
                key: keys.ksenc,
                message: message,
                iv: [UInt8](repeating: 0, count: 8)
            )
        }
        return AESDecrypt(
            key: keys.ksenc,
            message: message,
            iv: AESECBEncrypt(key: keys.ksenc, message: paddedSSC())
        )
    }

    static func dataObjects(_ bytes: [UInt8]) -> [(tag: UInt8, value: [UInt8], encoded: [UInt8])] {
        var objects: [(tag: UInt8, value: [UInt8], encoded: [UInt8])] = []
        var index = 0
        while index < bytes.count {
            let tag = bytes[index]
            guard index + 1 < bytes.count,
                  case let (length, lengthSize)? = try? asn1Length([UInt8](bytes[(index + 1)...])) else {
                break
            }
            let end = index + 1 + lengthSize + length
            guard end <= bytes.count else { break }
            objects.append((
                tag,
                [UInt8](bytes[(index + 1 + lengthSize) ..< end]),
                [UInt8](bytes[index ..< end])
            ))
            index = end
        }
        return objects
    }
}
