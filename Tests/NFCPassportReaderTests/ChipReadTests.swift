//
//  ChipReadTests.swift
//

import CoreNFC
import XCTest

@testable import AMANFCPassportReader

/// Data group reads against a simulated chip, APDU by APDU: how many round trips a file takes,
/// how the reader steps down when a chip refuses a read length, and how secure messaging carries
/// extended lengths. Every round trip costs about 115 ms on a slow chip, and iOS drops a connected
/// tag after about 20 s, so the counts here are what decides whether a large portrait fits.
final class ChipReadTests: XCTestCase {
    private let sodId: [UInt8] = [0x01, 0x1D]
    private let dg2Id: [UInt8] = [0x01, 0x02]

    // MARK: - Round trips

    func testSecurityObjectTakesFourteenRoundTripsInsteadOfNineteen() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.lastRead?.apdus, 14)
        XCTAssertEqual(reader.lastRead?.chunkLength, 223)
        XCTAssertEqual(chip.readBinaryExchanges.dropFirst().map(\.requestedLength).max(), 223)
    }

    func testUpstreamReadLengthStillTakesNineteenRoundTripsForTheSecurityObject() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, _) = makeReader(files: [sodId: sod])
        reader.overrideDataAmountToRead(newAmount: 0xA0)

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.lastRead?.apdus, 19)
    }

    func testTwentyKilobytePortraitTakesNinetyTwoRoundTripsInsteadOfOneHundredTwentySeven() async throws {
        let dg2 = Self.file(tag: 0x75, totalLength: 20_000)
        let (reader, _) = makeReader(files: [dg2Id: dg2])

        let data = try await reader.readDataGroup(dataGroup: .DG2)

        XCTAssertEqual(data, dg2)
        XCTAssertEqual(reader.lastRead?.apdus, 92)

        let (upstream, _) = makeReader(files: [dg2Id: dg2])
        upstream.overrideDataAmountToRead(newAmount: 0xA0)
        _ = try await upstream.readDataGroup(dataGroup: .DG2)
        XCTAssertEqual(upstream.lastRead?.apdus, 127)
    }

    func testStatedBuffersReadThePortraitInTwentyThreeRoundTrips() async throws {
        let dg2 = Self.file(tag: 0x75, totalLength: 20_000)
        let (reader, chip) = makeReader(files: [dg2Id: dg2])
        chip.acceptsExtendedLength = true
        chip.maxExtendedResponse = 1000
        XCTAssertTrue(reader.enableExtendedLengthReads(info: ExtendedLengthInfo(maxCommandLength: 1000, maxResponseLength: 1000)))

        let data = try await reader.readDataGroup(dataGroup: .DG2)

        XCTAssertEqual(data, dg2)
        // 1000-byte responses carry 975 plaintext bytes: 976 of cipher text and 24 of framing.
        XCTAssertEqual(reader.lastRead?.chunkLength, 975)
        XCTAssertEqual(reader.lastRead?.extendedLength, true)
        XCTAssertEqual(reader.lastRead?.apdus, 23)
        XCTAssertTrue(chip.readBinaryExchanges.allSatisfy { $0.responseBytes <= 1000 })
        XCTAssertTrue(chip.readBinaryExchanges.dropFirst().dropLast().allSatisfy(\.extendedLength))
    }

    func testExtendedResponsesAreCappedAtOneKilobyte() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.acceptsExtendedLength = true
        chip.maxExtendedResponse = 1024
        reader.enableExtendedLengthReads(info: ExtendedLengthInfo(maxCommandLength: 65535, maxResponseLength: 65535))

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.extendedResponseLimit, 1024)
        XCTAssertEqual(reader.lastRead?.chunkLength, 991)
        XCTAssertEqual(reader.lastRead?.apdus, 5)
    }

    func testThreeDESSessionsReadWithTheSameShortChunks() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod], algorithm: .DES)

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.lastRead?.apdus, 14)
        XCTAssertFalse(chip.readBinaryExchanges.contains(where: \.extendedLength))
    }

    // MARK: - Chips that refuse a read length

    func testRefusedExtendedReadFallsBackToShortChunksFromTheSameOffset() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.acceptsExtendedLength = true
        chip.maxReadLength = 223
        reader.enableExtendedLengthReads(info: ExtendedLengthInfo(maxCommandLength: 1000, maxResponseLength: 1000))

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        let reads = chip.readBinaryExchanges
        XCTAssertEqual(reads[1].status, 0x6700)
        XCTAssertEqual(reads[2].offset, reads[1].offset)
        XCTAssertEqual(reads[2].requestedLength, 223)
        XCTAssertNil(reader.extendedResponseLimit)
        XCTAssertEqual(reader.lastRead?.apdus, 15)
    }

    func testChipLimitedToUpstreamLengthStillReadsWhenItAnswersInsideSecureMessaging() async throws {
        // 9000 outside and 6700 in DO'99': the upstream status check took this as success
        // without data and asked for the same bytes until the session ended.
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.maxReadLength = 0xA0
        chip.protectedErrorsUseOuterSuccess = true

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.maxDataLengthToRead, 0xA0)
        XCTAssertEqual(reader.lastRead?.apdus, 20)
    }

    func testChipLimitedToUpstreamLengthStillReadsWhenItAnswersWithTheOuterStatus() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.maxReadLength = 0xA0

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.lastRead?.apdus, 20)
    }

    func testWrongLeWithExactLengthStepsDownToo() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.maxReadLength = 0xA0
        chip.wrongLength = (0x6C, 0xA0)

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.maxDataLengthToRead, 0xA0)
    }

    func testChipRefusingEvenTheUpstreamLengthFailsInsteadOfLooping() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.maxReadLength = 0x80
        chip.protectedErrorsUseOuterSuccess = true

        do {
            _ = try await reader.readDataGroup(dataGroup: .SOD)
            XCTFail("The read cannot succeed")
        } catch NFCPassportReaderError.ResponseError(_, let sw1, let sw2) {
            XCTAssertEqual([sw1, sw2], [0x67, 0x00])
        }
        XCTAssertEqual(chip.readBinaryExchanges.count, 3)
        XCTAssertEqual(reader.currentRead?.bytesRead, 4)
        XCTAssertEqual(reader.currentRead?.length, 2664)
    }

    func testReadsWithoutDataFailInsteadOfLooping() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.emptyReadsFromOffset = 500

        do {
            _ = try await reader.readDataGroup(dataGroup: .SOD)
            XCTFail("The read cannot succeed")
        } catch NFCPassportReaderError.ResponseError(let message, _, _) {
            XCTAssertEqual(message, "No data returned")
        }
        XCTAssertLessThan(chip.exchanges.count, 10)
    }

    func testExtendedLengthOnAChipWithoutItEndsSecureMessaging() async throws {
        // Why extended reads wait for stated buffer sizes: a chip that cannot parse the APDU
        // aborts secure messaging, and only a new PACE or BAC run would bring it back.
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        reader.enableExtendedLengthReads(info: ExtendedLengthInfo(maxCommandLength: 1000, maxResponseLength: 1000))

        do {
            _ = try await reader.readDataGroup(dataGroup: .SOD)
            XCTFail("The read cannot succeed")
        } catch NFCPassportReaderError.ResponseError(_, let sw1, let sw2) {
            XCTAssertEqual([sw1, sw2], [0x69, 0x87])
        }
        XCTAssertTrue(chip.secureMessagingAborted)
    }

    // MARK: - Secure messaging framing

    func testProtectedReadBinaryCarriesExtendedLengthsWhenAsked() throws {
        let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: Self.aesKey, ksmac: Self.aesKey.reversed(), ssc: [UInt8](repeating: 0, count: 8))

        let extended = try sm.protect(apdu: Self.readBinary(length: 991), useExtendedMode: true)
        XCTAssertEqual(extended.expectedResponseLength, 65536)
        XCTAssertEqual([UInt8](extended.data ?? Data()).prefix(4), [0x97, 0x02, 0x03, 0xDF])

        // 224 bytes no longer fit a short response under AES.
        let justOver = try sm.protect(apdu: Self.readBinary(length: 224), useExtendedMode: true)
        XCTAssertEqual(justOver.expectedResponseLength, 65536)

        // CoreNFC reports a short '00' Le as 0 and an extended '0000' one as 65536.
        let short = try sm.protect(apdu: Self.readBinary(length: 223), useExtendedMode: true)
        XCTAssertLessThanOrEqual(short.expectedResponseLength, 256)
        XCTAssertEqual([UInt8](short.data ?? Data()).prefix(3), [0x97, 0x01, 0xDF])
    }

    func testThreeDESKeepsShortFramingUpTo231Bytes() throws {
        let sm = SecureMessaging(encryptionAlgorithm: .DES, ksenc: Self.desKey, ksmac: Self.desKey.reversed(), ssc: [UInt8](repeating: 0, count: 8))

        XCTAssertLessThanOrEqual(try sm.protect(apdu: Self.readBinary(length: 231), useExtendedMode: true).expectedResponseLength, 256)
        XCTAssertEqual(try sm.protect(apdu: Self.readBinary(length: 232), useExtendedMode: true).expectedResponseLength, 65536)
    }

    func testExpectedLengthObjectEncodesEveryLength() throws {
        let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: Self.aesKey, ksmac: Self.aesKey, ssc: [UInt8](repeating: 0, count: 8))

        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 4)), [0x97, 0x01, 0x04])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 223)), [0x97, 0x01, 0xDF])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 256)), [0x97, 0x01, 0x00])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 991)), [0x97, 0x02, 0x03, 0xDF])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 1024)), [0x97, 0x02, 0x04, 0x00])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 4096)), [0x97, 0x02, 0x10, 0x00])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 65535)), [0x97, 0x02, 0xFF, 0xFF])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 65536)), [0x97, 0x02, 0x00, 0x00])
    }

    func testReadLengthLeavesRoomForTheSecureMessagingFraming() {
        XCTAssertEqual(TagReader.readLength(responseLimit: 258, blockSize: 16), 223)
        XCTAssertEqual(TagReader.readLength(responseLimit: 258, blockSize: 8), 231)
        XCTAssertEqual(TagReader.readLength(responseLimit: 1000, blockSize: 16), 975)
        XCTAssertEqual(TagReader.readLength(responseLimit: 1024, blockSize: 16), 991)
    }

    // MARK: - What the chip states

    func testATRInfoWithBufferSizesEnablesExtendedReads() async throws {
        let atrInfo: [UInt8] = [0x47, 0x03, 0x00, 0x00, 0x40, 0x7F, 0x66, 0x08, 0x02, 0x02, 0x03, 0xE8, 0x02, 0x02, 0x03, 0xE8]
        let chip = SimulatedChip(files: [[0x2F, 0x01]: atrInfo])
        let reader = TagReader(transport: chip)

        let bytes = try await reader.readATRInfo()

        XCTAssertEqual(bytes, atrInfo)
        let info = ExtendedLengthInfo.parse(atrInfo: atrInfo)
        XCTAssertEqual(info.maxCommandLength, 1000)
        XCTAssertEqual(info.maxResponseLength, 1000)
        XCTAssertEqual(info.indicatedByATRInfo, true)
        XCTAssertTrue(reader.enableExtendedLengthReads(info: info))
        XCTAssertEqual(reader.extendedResponseLimit, 1000)
    }

    func testMissingATRInfoKeepsShortReads() async throws {
        let chip = SimulatedChip(files: [:])
        let reader = TagReader(transport: chip)

        let bytes = try await reader.readATRInfo()

        XCTAssertNil(bytes)
        XCTAssertFalse(reader.enableExtendedLengthReads(info: ExtendedLengthInfo(indicatedByHistoricalBytes: true)))
        XCTAssertNil(reader.extendedResponseLimit)
    }

    func testCapabilityBitWithoutBufferSizesIsNotActedOn() {
        let info = ExtendedLengthInfo.parse(atrInfo: [0x47, 0x03, 0x00, 0x00, 0x40])

        XCTAssertEqual(info.indicatedByATRInfo, true)
        XCTAssertNil(info.usableResponseLimit)
    }

    func testOverriddenReadLengthIsKeptEvenWithStatedBuffers() {
        let reader = TagReader(transport: SimulatedChip(files: [:]))
        reader.overrideDataAmountToRead(newAmount: 0xA0)

        XCTAssertFalse(reader.enableExtendedLengthReads(info: ExtendedLengthInfo(maxCommandLength: 1000, maxResponseLength: 1000)))
    }

    func testHistoricalBytesCardCapabilities() {
        XCTAssertEqual(ExtendedLengthInfo.extendedLengthBit(historicalBytes: [0x80, 0x73, 0x00, 0x00, 0x40]), true)
        XCTAssertEqual(ExtendedLengthInfo.extendedLengthBit(historicalBytes: [0x80, 0x31, 0x80, 0x73, 0x00, 0x00, 0x80]), false)
        XCTAssertEqual(ExtendedLengthInfo.extendedLengthBit(historicalBytes: [0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x90, 0x00]), true)
        XCTAssertNil(ExtendedLengthInfo.extendedLengthBit(historicalBytes: [0x80, 0x31, 0x80]))
        XCTAssertNil(ExtendedLengthInfo.extendedLengthBit(historicalBytes: []))
    }

    func testDetectionReportsWhatTheChipStates() async throws {
        let atrInfo: [UInt8] = [0x7F, 0x66, 0x08, 0x02, 0x02, 0x04, 0x00, 0x02, 0x02, 0x04, 0x00]
        let chip = SimulatedChip(files: [[0x2F, 0x01]: atrInfo])
        chip.historicalBytes = Data([0x80, 0x73, 0x00, 0x00, 0x40])
        let reader = TagReader(transport: chip)

        let messages = await collect { await PassportReader().detectExtendedLength(tagReader: reader) }

        XCTAssertEqual(reader.extendedResponseLimit, 1024)
        XCTAssertTrue(messages.contains {
            $0.contains("historical bytes 80 73 00 00 40") && $0.contains("command 1024, response 1024 bytes")
                && $0.contains("responses up to 1024 bytes")
        }, "\(messages)")
    }

    func testCardAccessStillReadsInPlainMode() async throws {
        let cardAccess = Self.file(tag: 0x31, totalLength: 22)
        let chip = SimulatedChip(files: [[0x01, 0x1C]: cardAccess])
        let reader = TagReader(transport: chip)

        let data = try await reader.readCardAccess()

        XCTAssertEqual(data, cardAccess)
    }

    // MARK: - Read order

    func testRequestedDataGroupsAreReadInTheRequestedOrder() {
        let declared: [DataGroupId] = [.SOD, .DG1, .DG2, .DG11, .DG15]

        let order = PassportReader.readOrder(declared: declared, requested: [.COM, .DG14, .DG1, .DG2, .SOD, .DG11, .DG15], skipSecureElements: true)

        XCTAssertEqual(order, [.DG1, .DG2, .SOD, .DG11, .DG15])
    }

    func testDataGroupsTheChipDoesNotDeclareAreSkipped() {
        let order = PassportReader.readOrder(declared: [.SOD, .DG1, .DG2], requested: [.DG1, .DG2, .SOD, .DG11, .DG15], skipSecureElements: true)

        XCTAssertEqual(order, [.DG1, .DG2, .SOD])
    }

    func testReadingEverythingKeepsTheChipsOrderWithoutSecureElements() {
        let order = PassportReader.readOrder(declared: [.SOD, .DG1, .DG2, .DG3, .DG4, .DG14], requested: nil, skipSecureElements: true)

        XCTAssertEqual(order, [.SOD, .DG1, .DG2, .DG14])
    }
}

// MARK: - Private
private extension ChipReadTests {
    static let aesKey: [UInt8] = (0 ..< 32).map { UInt8($0 * 7 & 0xFF) }
    static let desKey: [UInt8] = (0 ..< 16).map { UInt8($0 * 13 & 0xFF) }

    func makeReader(files: [[UInt8]: [UInt8]], algorithm: SecureMessagingSupportedAlgorithms = .AES) -> (TagReader, SimulatedChip) {
        let key = algorithm == .AES ? Self.aesKey : Self.desKey
        let ksmac = [UInt8](key.reversed())
        let chip = SimulatedChip(files: files)
        chip.startSecureMessaging(algorithm: algorithm, ksenc: key, ksmac: ksmac)
        let reader = TagReader(transport: chip)
        reader.secureMessaging = SecureMessaging(encryptionAlgorithm: algorithm, ksenc: key, ksmac: ksmac, ssc: [UInt8](repeating: 0, count: 8))
        return (reader, chip)
    }

    /// A TLV file of `totalLength` bytes with a two-byte length (a one-byte one below 128 bytes).
    static func file(tag: UInt8, totalLength: Int) -> [UInt8] {
        let header: [UInt8] = totalLength - 2 < 0x80
            ? [tag, UInt8(totalLength - 2)]
            : [tag, 0x82, UInt8((totalLength - 4) >> 8), UInt8((totalLength - 4) & 0xFF)]
        let body = (0 ..< totalLength - header.count).map { UInt8(($0 * 31 + 17) & 0xFF) }
        return header + body
    }

    static func readBinary(length: Int) -> NFCISO7816APDU {
        NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xB0, p1Parameter: 0x00, p2Parameter: 0x00, data: Data(), expectedResponseLength: length)
    }

    func collect(_ body: () async -> Void) async -> [String] {
        let box = MessageBox()
        let observer = NotificationCenter.default.addObserver(forName: PassportReaderDiagnostics.notificationName, object: nil, queue: nil) { notification in
            if let message = notification.userInfo?["message"] as? String {
                box.append(message)
            }
        }
        defer { NotificationCenter.default.removeObserver(observer) }
        await body()
        return box.messages
    }
}

private final class MessageBox: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [String] = []

    var messages: [String] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    func append(_ message: String) {
        lock.lock()
        stored.append(message)
        lock.unlock()
    }
}
