//
//  ChipReadTests.swift
//

import CoreNFC
import XCTest

@testable import AMANFCPassportReader

/// Data group reads against a simulated chip, APDU by APDU: how many round trips a file takes,
/// how the reader falls back when a chip refuses a read, and how secure messaging carries
/// extended lengths. Every round trip costs about 115 ms on a slow chip, and iOS drops a connected
/// tag after about 20 s, so the counts here are what decides whether a large portrait fits.
final class ChipReadTests: XCTestCase {
    private let comId: [UInt8] = [0x01, 0x1E]
    private let dg1Id: [UInt8] = [0x01, 0x01]
    private let dg2Id: [UInt8] = [0x01, 0x02]
    private let sodId: [UInt8] = [0x01, 0x1D]

    // MARK: - Round trips

    func testSecurityObjectTakesTwelveRoundTripsInsteadOfNineteen() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.lastRead?.apdus, 12)
        XCTAssertEqual(reader.lastRead?.chunkLength, 223)
        XCTAssertEqual(chip.readBinaryExchanges.map(\.requestedLength).max(), 223)
        XCTAssertEqual(chip.readBinaryExchanges.first?.p1, 0x9D)
        XCTAssertFalse(chip.exchanges.contains { $0.instruction == 0xA4 })
    }

    func testUpstreamReadingStillTakesNineteenRoundTripsForTheSecurityObject() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, _) = makeReader(files: [sodId: sod])
        readLikeUpstream(reader)

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.lastRead?.apdus, 19)
    }

    func testTwentyKilobytePortraitTakesNinetyRoundTripsInsteadOfOneHundredTwentySeven() async throws {
        let dg2 = Self.file(tag: 0x75, totalLength: 20_000)
        let (reader, _) = makeReader(files: [dg2Id: dg2])

        let data = try await reader.readDataGroup(dataGroup: .DG2)

        XCTAssertEqual(data, dg2)
        XCTAssertEqual(reader.lastRead?.apdus, 90)

        let (upstream, _) = makeReader(files: [dg2Id: dg2])
        readLikeUpstream(upstream)
        _ = try await upstream.readDataGroup(dataGroup: .DG2)
        XCTAssertEqual(upstream.lastRead?.apdus, 127)
    }

    func testStatedBuffersReadThePortraitInTwentyOneRoundTrips() async throws {
        let dg2 = Self.file(tag: 0x75, totalLength: 20_000)
        let (reader, chip) = makeReader(files: [dg2Id: dg2])
        chip.acceptsExtendedLength = true
        chip.maxExtendedResponse = 1000
        let info = ExtendedLengthInfo(maxCommandLength: 1000, maxResponseLength: 1000)
        XCTAssertTrue(reader.enableExtendedLengthReads(info: info))

        let data = try await reader.readDataGroup(dataGroup: .DG2)

        XCTAssertEqual(data, dg2)
        // 1000-byte responses carry 975 plaintext bytes: 976 of cipher text and 24 of framing.
        XCTAssertEqual(reader.lastRead?.chunkLength, 975)
        XCTAssertEqual(reader.lastRead?.extendedLength, true)
        XCTAssertEqual(reader.lastRead?.apdus, 21)
        XCTAssertTrue(chip.readBinaryExchanges.allSatisfy { $0.responseBytes <= 1000 })
        XCTAssertTrue(chip.readBinaryExchanges.dropLast().allSatisfy(\.extendedLength))
    }

    func testExtendedResponsesAreCappedAtOneKilobyte() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.acceptsExtendedLength = true
        chip.maxExtendedResponse = 1024
        reader.enableExtendedLengthReads(info: ExtendedLengthInfo(
            maxCommandLength: 65535,
            maxResponseLength: 65535
        ))

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.extendedResponseLimit, 1024)
        XCTAssertEqual(reader.lastRead?.chunkLength, 991)
        XCTAssertEqual(reader.lastRead?.apdus, 3)
    }

    func testThreeDESSessionsReadWithTheSameShortChunks() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod], algorithm: .DES)

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(reader.lastRead?.apdus, 12)
        XCTAssertFalse(chip.readBinaryExchanges.contains(where: \.extendedLength))
    }

    // MARK: - First read

    func testSmallFileTakesOneRoundTripAndLeavesTheFilePaddingOut() async throws {
        let com = Self.file(tag: 0x60, totalLength: 25)
        let (reader, chip) = makeReader(files: [comId: com + [UInt8](repeating: 0x00, count: 20)])

        let data = try await reader.readDataGroup(dataGroup: .COM)

        XCTAssertEqual(data, com)
        XCTAssertEqual(reader.lastRead?.apdus, 1)
        XCTAssertEqual(chip.readBinaryExchanges.first?.p1, 0x9E)
        XCTAssertEqual(chip.readBinaryExchanges.first?.status, 0x6282)
    }

    func testEveryWayOfAnsweringAReadPastTheEndIsAccepted() async throws {
        let com = Self.file(tag: 0x60, totalLength: 25)
        let answers: [SimulatedChip.PastEndOfFile] = [.warning, .success]
        for algorithm in [SecureMessagingSupportedAlgorithms.AES, .DES] {
            for answer in answers {
                for outerSuccess in [false, true] {
                    let (reader, chip) = makeReader(files: [comId: com], algorithm: algorithm)
                    chip.pastEndOfFile = answer
                    chip.protectedErrorsUseOuterSuccess = outerSuccess

                    let data = try await reader.readDataGroup(dataGroup: .COM)

                    let setup = "\(algorithm) \(answer) outer success \(outerSuccess)"
                    XCTAssertEqual(data, com, setup)
                    XCTAssertEqual(reader.lastRead?.apdus, 1, setup)
                }
            }
        }
    }

    func testExactLengthAnswerIsReadAgainAtThatLength() async throws {
        let com = Self.file(tag: 0x60, totalLength: 25)
        let (reader, chip) = makeReader(files: [comId: com])
        chip.pastEndOfFile = .exactLength

        let data = try await reader.readDataGroup(dataGroup: .COM)

        XCTAssertEqual(data, com)
        XCTAssertEqual(chip.readBinaryExchanges.map(\.requestedLength), [223, 25])
        XCTAssertTrue(reader.readsWholeFirstChunk)
    }

    func testChipThatWillNotReadPastTheEndGetsTheHeaderFirstFromThenOn() async throws {
        let com = Self.file(tag: 0x60, totalLength: 25)
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [comId: com, sodId: sod])
        chip.pastEndOfFile = .refused(0x67, 0x00)

        let comData = try await reader.readDataGroup(dataGroup: .COM)
        let comAPDUs = reader.lastRead?.apdus
        let sodData = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(comData, com)
        XCTAssertEqual(sodData, sod)
        XCTAssertEqual(comAPDUs, 3)
        XCTAssertEqual(reader.lastRead?.apdus, 13)
        XCTAssertFalse(reader.readsWholeFirstChunk)
        XCTAssertTrue(reader.readsByShortFileIdentifier)
        XCTAssertFalse(chip.exchanges.contains { $0.instruction == 0xA4 })
    }

    func testChipWithoutShortFileIdentifiersIsSelectedFromThenOn() async throws {
        let com = Self.file(tag: 0x60, totalLength: 25)
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [comId: com, sodId: sod])
        chip.shortFileIdentifierRefusal = (0x6A, 0x86)

        let comData = try await reader.readDataGroup(dataGroup: .COM)
        let comAPDUs = reader.lastRead?.apdus
        let sodData = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(comData, com)
        XCTAssertEqual(sodData, sod)
        XCTAssertEqual(comAPDUs, 3)
        XCTAssertEqual(reader.lastRead?.apdus, 13)
        XCTAssertFalse(reader.readsByShortFileIdentifier)
        XCTAssertTrue(reader.readsWholeFirstChunk)
    }

    func testMissingFileFailsAsBeforeAndKeepsShortFileIdentifiers() async throws {
        let (reader, _) = makeReader(files: [:])

        do {
            _ = try await reader.readDataGroup(dataGroup: .DG11)
            XCTFail("The read cannot succeed")
        } catch let NFCPassportReaderError.ResponseError(message, sw1, sw2) {
            XCTAssertEqual(message, "File not found")
            XCTAssertEqual([sw1, sw2], [0x6A, 0x82])
        }
        XCTAssertTrue(reader.readsByShortFileIdentifier)
    }

    // MARK: - Chips that refuse a read length

    func testRefusedExtendedFirstReadFallsBackToShortChunks() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.acceptsExtendedLength = true
        chip.maxReadLength = 223
        reader.enableExtendedLengthReads(info: ExtendedLengthInfo(
            maxCommandLength: 1000,
            maxResponseLength: 1000
        ))

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        XCTAssertEqual(chip.readBinaryExchanges.first?.status, 0x6700)
        XCTAssertNil(reader.extendedResponseLimit)
        XCTAssertTrue(reader.readsWholeFirstChunk)
        XCTAssertEqual(reader.lastRead?.apdus, 13)
    }

    func testRefusedExtendedReadFallsBackToShortChunksFromTheSameOffset() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.acceptsExtendedLength = true
        chip.maxReadLength = 223
        reader.readsWholeFirstChunk = false
        reader.enableExtendedLengthReads(info: ExtendedLengthInfo(
            maxCommandLength: 1000,
            maxResponseLength: 1000
        ))

        let data = try await reader.readDataGroup(dataGroup: .SOD)

        XCTAssertEqual(data, sod)
        let reads = chip.readBinaryExchanges
        XCTAssertEqual(reads[1].status, 0x6700)
        XCTAssertEqual(reads[2].offset, reads[1].offset)
        XCTAssertEqual(reads[2].requestedLength, 223)
        XCTAssertNil(reader.extendedResponseLimit)
        XCTAssertEqual(reader.lastRead?.apdus, 14)
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
        } catch let NFCPassportReaderError.ResponseError(_, sw1, sw2) {
            XCTAssertEqual([sw1, sw2], [0x67, 0x00])
        }
        XCTAssertEqual(chip.readBinaryExchanges.count, 4)
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
        } catch let NFCPassportReaderError.ResponseError(message, _, _) {
            XCTAssertEqual(message, "No data returned")
        }
        XCTAssertLessThan(chip.exchanges.count, 10)
    }

    func testPlainRefusalEndsTheReadAndLowersTheLengthForTheNextSession() async throws {
        // A plain status word under secure messaging means the chip has left it: asking again
        // on the same keys only earns 6988, so the refusal goes up to establish access again.
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.maxReadLength = 0xA0
        chip.refusesLengthInPlain = true
        reader.readsWholeFirstChunk = false

        do {
            _ = try await reader.readDataGroup(dataGroup: .SOD)
            XCTFail("The read cannot succeed")
        } catch let NFCPassportReaderError.ResponseError(_, sw1, sw2) {
            XCTAssertEqual([sw1, sw2], [0x67, 0x00])
        }
        XCTAssertEqual(chip.readBinaryExchanges.count, 2)
        XCTAssertEqual(reader.maxDataLengthToRead, 0xA0)
        XCTAssertFalse(reader.lastResponseKeptSecureMessaging)
    }

    func testPlainRefusalOfTheFirstReadIsThrown() async throws {
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.maxReadLength = 0xA0
        chip.refusesLengthInPlain = true

        do {
            _ = try await reader.readDataGroup(dataGroup: .SOD)
            XCTFail("The read cannot succeed")
        } catch let NFCPassportReaderError.ResponseError(_, sw1, sw2) {
            XCTAssertEqual([sw1, sw2], [0x67, 0x00])
        }
        XCTAssertEqual(chip.exchanges.count, 1)
        XCTAssertFalse(reader.readsByShortFileIdentifier)
        XCTAssertFalse(reader.readsWholeFirstChunk)
    }

    func testExtendedLengthOnAChipWithoutItEndsSecureMessaging() async throws {
        // Why extended reads wait for stated buffer sizes: a chip that cannot parse the APDU
        // aborts secure messaging, and only a new PACE or BAC run would bring it back.
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        reader.enableExtendedLengthReads(info: ExtendedLengthInfo(
            maxCommandLength: 1000,
            maxResponseLength: 1000
        ))

        do {
            _ = try await reader.readDataGroup(dataGroup: .SOD)
            XCTFail("The read cannot succeed")
        } catch let NFCPassportReaderError.ResponseError(_, sw1, sw2) {
            XCTAssertEqual([sw1, sw2], [0x67, 0x00])
        }
        XCTAssertTrue(chip.secureMessagingAborted)
        XCTAssertEqual(chip.exchanges.count, 1)
        XCTAssertNil(reader.extendedResponseLimit)
    }

    func testTransportErrorIsThrownWithoutAnotherAttempt() async throws {
        // The command was already protected, so secure messaging is out of step: nothing in
        // this session can be read any more without establishing access again.
        let sod = Self.file(tag: 0x77, totalLength: 2664)
        let (reader, chip) = makeReader(files: [sodId: sod])
        chip.acceptsExtendedLength = true
        let transport = FailingTransport(chip: chip)
        reader.tag = transport
        reader.enableExtendedLengthReads(info: ExtendedLengthInfo(
            maxCommandLength: 1000,
            maxResponseLength: 1000
        ))

        do {
            _ = try await reader.readDataGroup(dataGroup: .SOD)
            XCTFail("The read cannot succeed")
        } catch let error as NFCReaderError {
            XCTAssertEqual(error.code, .readerTransceiveErrorPacketTooLong)
        }
        XCTAssertEqual(transport.attempts, 1)
        XCTAssertTrue(chip.exchanges.isEmpty)
    }

    func testReadsPastThirtyTwoKilobytesStopInsteadOfAddressingAnotherFile() async throws {
        // READ BINARY carries a 15-bit offset: with P1 b8 set the chip reads a short file
        // identifier, and the portrait would take another file's bytes.
        let dg2 = Self.file(tag: 0x75, totalLength: 40_000)
        let (reader, chip) = makeReader(files: [dg2Id: dg2])

        do {
            _ = try await reader.readDataGroup(dataGroup: .DG2)
            XCTFail("The read cannot succeed")
        } catch let NFCPassportReaderError.NotYetSupported(message) {
            XCTAssertTrue(message.contains("32767"), message)
        }
        let reads = chip.readBinaryExchanges
        XCTAssertEqual(reads.first?.p1, 0x82)
        XCTAssertTrue(reads.dropFirst().allSatisfy { $0.p1 < 0x80 })
        XCTAssertLessThanOrEqual(reads.map(\.offset).max() ?? 0, 0x7FFF)
    }

    // MARK: - Secure messaging framing

    func testProtectedReadBinaryCarriesExtendedLengthsWhenAsked() throws {
        let sm = SecureMessaging(
            encryptionAlgorithm: .AES,
            ksenc: Self.aesKey,
            ksmac: Self.aesKey.reversed(),
            ssc: [UInt8](repeating: 0, count: 8)
        )

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
        let sm = SecureMessaging(
            encryptionAlgorithm: .DES,
            ksenc: Self.desKey,
            ksmac: Self.desKey.reversed(),
            ssc: [UInt8](repeating: 0, count: 8)
        )

        let longest = try sm.protect(apdu: Self.readBinary(length: 231), useExtendedMode: true)
        XCTAssertLessThanOrEqual(longest.expectedResponseLength, 256)
        let tooLong = try sm.protect(apdu: Self.readBinary(length: 232), useExtendedMode: true)
        XCTAssertEqual(tooLong.expectedResponseLength, 65536)
    }

    func testExpectedLengthObjectEncodesEveryLength() throws {
        let sm = SecureMessaging(
            encryptionAlgorithm: .AES,
            ksenc: Self.aesKey,
            ksmac: Self.aesKey,
            ssc: [UInt8](repeating: 0, count: 8)
        )

        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 4)), [0x97, 0x01, 0x04])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 223)), [0x97, 0x01, 0xDF])
        XCTAssertEqual(try sm.buildD097(apdu: Self.readBinary(length: 256)), [0x97, 0x01, 0x00])
        XCTAssertEqual(
            try sm.buildD097(apdu: Self.readBinary(length: 991)),
            [0x97, 0x02, 0x03, 0xDF]
        )
        XCTAssertEqual(
            try sm.buildD097(apdu: Self.readBinary(length: 1024)),
            [0x97, 0x02, 0x04, 0x00]
        )
        XCTAssertEqual(
            try sm.buildD097(apdu: Self.readBinary(length: 4096)),
            [0x97, 0x02, 0x10, 0x00]
        )
        XCTAssertEqual(
            try sm.buildD097(apdu: Self.readBinary(length: 65535)),
            [0x97, 0x02, 0xFF, 0xFF]
        )
        XCTAssertEqual(
            try sm.buildD097(apdu: Self.readBinary(length: 65536)),
            [0x97, 0x02, 0x00, 0x00]
        )
    }

    func testReadLengthLeavesRoomForTheSecureMessagingFraming() {
        XCTAssertEqual(TagReader.readLength(responseLimit: 258, blockSize: 16), 223)
        XCTAssertEqual(TagReader.readLength(responseLimit: 258, blockSize: 8), 231)
        XCTAssertEqual(TagReader.readLength(responseLimit: 1000, blockSize: 16), 975)
        XCTAssertEqual(TagReader.readLength(responseLimit: 1024, blockSize: 16), 991)
    }

    // MARK: - What the chip states

    func testATRInfoWithBufferSizesEnablesExtendedReads() async throws {
        let atrInfo: [UInt8] = [
            0x47, 0x03, 0x00, 0x00, 0x40,
            0x7F, 0x66, 0x08, 0x02, 0x02, 0x03, 0xE8, 0x02, 0x02, 0x03, 0xE8
        ]
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

        let info = ExtendedLengthInfo(maxCommandLength: 1000, maxResponseLength: 1000)
        XCTAssertFalse(reader.enableExtendedLengthReads(info: info))
    }

    func testHistoricalBytesCardCapabilities() {
        XCTAssertEqual(
            ExtendedLengthInfo.extendedLengthBit(historicalBytes: [0x80, 0x73, 0x00, 0x00, 0x40]),
            true
        )
        XCTAssertEqual(
            ExtendedLengthInfo.extendedLengthBit(historicalBytes: [
                0x80,
                0x31,
                0x80,
                0x73,
                0x00,
                0x00,
                0x80
            ]),
            false
        )
        XCTAssertEqual(
            ExtendedLengthInfo.extendedLengthBit(historicalBytes: [
                0x00,
                0x73,
                0x00,
                0x00,
                0x40,
                0x00,
                0x90,
                0x00
            ]),
            true
        )
        XCTAssertNil(ExtendedLengthInfo.extendedLengthBit(historicalBytes: [0x80, 0x31, 0x80]))
        XCTAssertNil(ExtendedLengthInfo.extendedLengthBit(historicalBytes: []))
    }

    func testDetectionReportsWhatTheChipStatesWhenExtendedReadsAreOn() async throws {
        let atrInfo: [UInt8] = [0x7F, 0x66, 0x08, 0x02, 0x02, 0x04, 0x00, 0x02, 0x02, 0x04, 0x00]
        let chip = SimulatedChip(files: [[0x2F, 0x01]: atrInfo])
        chip.historicalBytes = Data([0x80, 0x73, 0x00, 0x00, 0x40])
        let reader = TagReader(transport: chip)
        let passportReader = PassportReader()
        passportReader.extendedLengthReads = true

        let messages = await collect { await passportReader.detectExtendedLength(tagReader: reader) }

        XCTAssertEqual(reader.extendedResponseLimit, 1024)
        XCTAssertTrue(messages.contains {
            $0.contains("historical bytes 80 73 00 00 40") && $0.contains("command 1024, response 1024 bytes")
                && $0.contains("responses up to 1024 bytes")
        }, "\(messages)")
    }

    func testDetectionLeavesEFATRInfoAloneWhileExtendedReadsAreOff() async throws {
        let atrInfo: [UInt8] = [0x7F, 0x66, 0x08, 0x02, 0x02, 0x04, 0x00, 0x02, 0x02, 0x04, 0x00]
        let chip = SimulatedChip(files: [[0x2F, 0x01]: atrInfo])
        chip.historicalBytes = Data([0x80, 0x73, 0x00, 0x00, 0x40])
        let reader = TagReader(transport: chip)

        let messages = await collect { await PassportReader().detectExtendedLength(tagReader: reader) }

        XCTAssertTrue(chip.exchanges.isEmpty)
        XCTAssertNil(reader.extendedResponseLimit)
        XCTAssertTrue(messages.contains {
            $0.contains("historical bytes 80 73 00 00 40 (extended length)") && $0.contains("extended-length reads off")
                && $0.contains("223-byte chunks")
        }, "\(messages)")
    }

    func testBACOnlySessionChecksExtendedLengthFromTheMasterFileAndReselectsTheApplication() async throws {
        let atrInfo: [UInt8] = [0x7F, 0x66, 0x08, 0x02, 0x02, 0x04, 0x00, 0x02, 0x02, 0x04, 0x00]
        let chip = SimulatedChip(files: [[0x2F, 0x01]: atrInfo])
        let reader = TagReader(transport: chip)
        let passportReader = PassportReader()
        passportReader.extendedLengthReads = true

        await passportReader.detectExtendedLengthWithoutPACE(tagReader: reader)

        XCTAssertEqual(reader.extendedResponseLimit, 1024)
        let selects = chip.exchanges.filter { $0.instruction == 0xA4 }.map(\.p1)
        XCTAssertEqual(selects.first, 0x00)
        XCTAssertEqual(selects.last, 0x04)
    }

    func testBACOnlySessionSendsNothingForExtendedLengthWhileItIsOff() async {
        let chip = SimulatedChip(files: [:])
        chip.historicalBytes = Data([0x80, 0x73, 0x00, 0x00, 0x40])
        let reader = TagReader(transport: chip)

        let messages = await collect { await PassportReader().detectExtendedLengthWithoutPACE(tagReader: reader) }

        XCTAssertTrue(chip.exchanges.isEmpty)
        XCTAssertTrue(messages.contains { $0.contains("extended-length reads off") }, "\(messages)")
    }

    func testClearedReadLengthOverrideNoLongerReachesTheNextSession() async {
        let (reader, _) = makeReader(files: [:])
        let passportReader = PassportReader()
        passportReader.overrideNFCDataAmountToRead(amount: 0xA0)

        let overridden = await collect { passportReader.attachDiagnostics(to: reader) }
        passportReader.clearNFCDataAmountOverride()
        let cleared = await collect { passportReader.attachDiagnostics(to: reader) }

        XCTAssertTrue(overridden.contains { $0.contains("read length 160 bytes (host override)") }, "\(overridden)")
        XCTAssertTrue(cleared.contains { $0.contains("Reader options") && !$0.contains("host override") }, "\(cleared)")
    }

    func testCardAccessStillReadsInPlainModeTheUpstreamWay() async throws {
        let cardAccess = Self.file(tag: 0x31, totalLength: 22)
        let chip = SimulatedChip(files: [[0x01, 0x1C]: cardAccess])
        let reader = TagReader(transport: chip)

        let data = try await reader.readCardAccess()

        XCTAssertEqual(data, cardAccess)
        XCTAssertEqual(chip.readBinaryExchanges.first?.requestedLength, 4)
        XCTAssertTrue(chip.readBinaryExchanges.allSatisfy { $0.p1 < 0x80 })
    }

    // MARK: - Read order

    func testRequestedDataGroupsAreReadInTheRequestedOrder() {
        let declared: [DataGroupId] = [.SOD, .DG1, .DG2, .DG11, .DG15]

        let order = PassportReader.readOrder(
            declared: declared,
            requested: [.COM, .DG14, .DG1, .DG2, .SOD, .DG11, .DG15],
            skipSecureElements: true
        )

        XCTAssertEqual(order, [.DG1, .DG2, .SOD, .DG11, .DG15])
    }

    func testDataGroupsTheChipDoesNotDeclareAreSkipped() {
        let order = PassportReader.readOrder(
            declared: [.SOD, .DG1, .DG2],
            requested: [.DG1, .DG2, .SOD, .DG11, .DG15],
            skipSecureElements: true
        )

        XCTAssertEqual(order, [.DG1, .DG2, .SOD])
    }

    func testReadingEverythingKeepsTheChipsOrderWithoutSecureElements() {
        let order = PassportReader.readOrder(
            declared: [.SOD, .DG1, .DG2, .DG3, .DG4, .DG14],
            requested: nil,
            skipSecureElements: true
        )

        XCTAssertEqual(order, [.SOD, .DG1, .DG2, .DG14])
    }

    func testSecureElementsAreSkippedEvenWhenAskedForByName() {
        let order = PassportReader.readOrder(
            declared: [.SOD, .DG1, .DG2, .DG3, .DG4],
            requested: [.DG1, .DG3, .DG4, .DG2],
            skipSecureElements: true
        )

        XCTAssertEqual(order, [.DG1, .DG2])
    }

    // DG3 and DG4 open only after Terminal Authentication, which this reader does not
    // perform: asking for them only draws a 6982 and a secure-messaging restart.
    func testSessionNeverAsksTheChipForDG3OrDG4() async throws {
        let com = try Self.com(declaring: [0x61, 0x63, 0x76])
        let dg1 = try Self.dataGroup1()
        let dg3 = Self.file(tag: 0x63, totalLength: 40)
        let dg4 = Self.file(tag: 0x76, totalLength: 40)
        let (reader, chip) = makeReader(files: [comId: com, dg1Id: dg1, [0x01, 0x03]: dg3, [0x01, 0x04]: dg4])
        let passportReader = PassportReader()
        passportReader.dataGroupsToRead = [.COM, .DG1, .DG3, .DG4]
        passportReader.readAllDatagroups = false

        try await passportReader.readDataGroups(tagReader: reader)

        let firstReads = chip.readBinaryExchanges.filter { $0.p1 & 0x80 != 0 }.map(\.p1)
        XCTAssertEqual(firstReads, [0x9E, 0x81])
        XCTAssertEqual(reader.apduCount, 2)
        XCTAssertFalse(chip.exchanges.contains { $0.instruction == 0xA4 })
    }

    func testSessionReadsCOMThenTheRequestedGroupsInOrder() async throws {
        let com = try Self.com(declaring: [0x61, 0x75])
        let dg1 = try Self.dataGroup1()
        let dg2 = try Self.dataGroup2(imageBytes: 500)
        let (reader, chip) = makeReader(files: [comId: com, dg1Id: dg1, dg2Id: dg2])
        let passportReader = PassportReader()
        passportReader.dataGroupsToRead = [.COM, .DG2, .DG1]
        passportReader.readAllDatagroups = false

        try await passportReader.readDataGroups(tagReader: reader)

        let firstReads = chip.readBinaryExchanges.filter { $0.p1 & 0x80 != 0 }.map(\.p1)
        XCTAssertEqual(firstReads, [0x9E, 0x82, 0x81])
        // COM and DG1 fit one APDU each, the 5xx-byte DG2 takes three.
        XCTAssertEqual(reader.apduCount, 5)
        XCTAssertFalse(chip.exchanges.contains { $0.instruction == 0xA4 })
    }

    // MARK: - Session log

    func testAPDUTraceReportsEveryCommandWithoutItsBytes() async throws {
        let com = try Self.com(declaring: [0x61, 0x75])
        let dg1 = try Self.dataGroup1()
        let dg2 = try Self.dataGroup2(imageBytes: 500)
        let (reader, _) = makeReader(files: [comId: com, dg1Id: dg1, dg2Id: dg2])
        let passportReader = sessionReader(reading: [.COM, .DG2, .DG1], apduTrace: true)
        passportReader.attachDiagnostics(to: reader)

        let messages = await collect { try? await passportReader.readDataGroups(tagReader: reader) }

        let trace = messages.filter { $0.contains("[apdu]") }
        XCTAssertEqual(trace.count, reader.apduCount)
        // COM is shorter than the chunk asked for: the chip answers with the end-of-file warning.
        XCTAssertTrue(trace.contains { $0.contains("APDU 1 READ BINARY SFI 1E offset 0, Le 223, SM - \(com.count) B, SW 6282, round trip ") }, "\(trace)")
        XCTAssertTrue(trace.contains { $0.contains("APDU 3 READ BINARY offset 223, Le 223, SM - 223 B, SW 9000, round trip ") && $0.contains(", phone ") }, "\(trace)")
        XCTAssertFalse(trace.contains { $0.contains("resumed") }, "\(trace)")
        let mrzBytes = [UInt8]("THATCHER".utf8)
        let mrzHex = mrzBytes.map { String(format: "%02X", $0) }
        for message in messages {
            XCTAssertFalse(message.contains("THATCHER"))
            XCTAssertFalse(message.contains(mrzHex.joined()))
            XCTAssertFalse(message.contains(mrzHex.joined(separator: " ")))
        }
    }

    func testAPDUTraceShowsTheWaitAfterCoreNFCAnswers() async throws {
        let com = try Self.com(declaring: [0x61])
        let (simulated, chip) = makeReader(files: [comId: com])
        let reader = TagReader(transport: LateResumingTransport(chip: chip))
        reader.secureMessaging = simulated.secureMessaging
        let passportReader = sessionReader(reading: [.COM], apduTrace: true)
        passportReader.attachDiagnostics(to: reader)

        let messages = await collect { try? await passportReader.readDataGroups(tagReader: reader) }

        let trace = messages.filter { $0.contains("[apdu]") }
        XCTAssertFalse(trace.isEmpty)
        XCTAssertTrue(trace.allSatisfy { $0.contains(" ms (resumed ") && $0.contains(" ms after CoreNFC answered)") }, "\(trace)")
    }

    func testReaderOptionsNameTheSessionQueue() async {
        let (reader, _) = makeReader(files: [:])
        let passportReader = sessionReader(reading: [.COM], apduTrace: false)

        let mainQueue = await collect { passportReader.attachDiagnostics(to: reader) }
        passportReader.dedicatedSessionQueue = true
        let dedicatedQueue = await collect { passportReader.attachDiagnostics(to: reader) }

        XCTAssertTrue(mainQueue.contains { $0.contains("Reader options") && $0.contains("session callbacks on the main queue") }, "\(mainQueue)")
        XCTAssertTrue(dedicatedQueue.contains { $0.contains("Reader options") && $0.contains("session callbacks on a dedicated queue") }, "\(dedicatedQueue)")
    }

    // MUTUAL AUTHENTICATE carries the BAC key material: its trace may give the length only.
    func testAPDUTraceLeavesAuthenticationDataOut() async {
        let chip = SimulatedChip(files: [:])
        let reader = TagReader(transport: chip)
        let passportReader = sessionReader(reading: [.COM], apduTrace: true)
        passportReader.attachDiagnostics(to: reader)
        let secret: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xC0, 0xDE]

        let messages = await collect { _ = try? await reader.doMutualAuthentication(cmdData: Data(secret)) }

        XCTAssertTrue(messages.contains { $0.contains("MUTUAL AUTHENTICATE P1P2 0000, Lc 8, Le 256, plain") }, "\(messages)")
        XCTAssertFalse(messages.contains { $0.uppercased().contains("DEADBEEF") || $0.uppercased().contains("DE AD BE EF") })
    }

    func testAPDUTraceReportsACommandThatFailsInTransit() async throws {
        let com = try Self.com(declaring: [0x61])
        let (simulated, chip) = makeReader(files: [comId: com])
        let underlying = NSError(domain: "ProbeTransport", code: 7)
        let failure = NSError(domain: "ProbeSession", code: 42, userInfo: [NSUnderlyingErrorKey: underlying])
        let reader = TagReader(transport: ThrowingTransport(chip: chip, error: failure))
        reader.secureMessaging = simulated.secureMessaging
        let passportReader = sessionReader(reading: [.COM], apduTrace: true)
        passportReader.attachDiagnostics(to: reader)

        let messages = await collect { try? await passportReader.readDataGroups(tagReader: reader) }

        let trace = messages.filter { $0.contains("[apdu]") }
        XCTAssertTrue(trace.contains {
            $0.contains("APDU 1 READ BINARY SFI 1E offset 0, Le 223, SM - failed: ProbeSession 42: ")
                && $0.contains("(underlying ProbeTransport 7), round trip ")
        }, "\(trace)")
    }

    func testAPDUTraceIsOffByDefault() async throws {
        let com = try Self.com(declaring: [0x61])
        let dg1 = try Self.dataGroup1()
        let (reader, _) = makeReader(files: [comId: com, dg1Id: dg1])
        let passportReader = sessionReader(reading: [.COM, .DG1], apduTrace: false)
        passportReader.attachDiagnostics(to: reader)

        let messages = await collect { try? await passportReader.readDataGroups(tagReader: reader) }

        XCTAssertFalse(messages.contains { $0.contains("[apdu]") })
        XCTAssertTrue(messages.contains { $0.contains("DG1 read - ") })
    }

    // A session that dies halfway through the portrait must still say how large it was.
    func testPortraitLengthIsReportedAsSoonAsItsFirstChunkArrives() async throws {
        let com = try Self.com(declaring: [0x75])
        let dg2 = try Self.dataGroup2(imageBytes: 20_000)
        let (reader, _) = makeReader(files: [comId: com, dg2Id: dg2])
        let passportReader = sessionReader(reading: [.COM, .DG2], apduTrace: false)
        passportReader.attachDiagnostics(to: reader)

        let messages = await collect { try? await passportReader.readDataGroups(tagReader: reader) }

        let apdusLeft = (dg2.count - 223 + 222) / 223
        XCTAssertTrue(messages.contains {
            $0.contains("DG2 is \(dg2.count) bytes - \(apdusLeft) more APDUs in 223-byte chunks, ~") && $0.contains("ms per APDU so far")
        }, "\(messages)")
    }
}

// MARK: - Private
private extension ChipReadTests {
    func sessionReader(reading dataGroups: [DataGroupId], apduTrace: Bool) -> PassportReader {
        let passportReader = PassportReader()
        passportReader.apduTrace = apduTrace
        passportReader.dataGroupsToRead = dataGroups
        passportReader.readAllDatagroups = false
        return passportReader
    }

    static let aesKey: [UInt8] = (0 ..< 32).map { UInt8($0 * 7 & 0xFF) }
    static let desKey: [UInt8] = (0 ..< 16).map { UInt8($0 * 13 & 0xFF) }

    func makeReader(
        files: [[UInt8]: [UInt8]],
        algorithm: SecureMessagingSupportedAlgorithms = .AES
    ) -> (TagReader, SimulatedChip) {
        let key = algorithm == .AES ? Self.aesKey : Self.desKey
        let ksmac = [UInt8](key.reversed())
        let chip = SimulatedChip(files: files)
        chip.startSecureMessaging(algorithm: algorithm, ksenc: key, ksmac: ksmac)
        let reader = TagReader(transport: chip)
        reader.secureMessaging = SecureMessaging(
            encryptionAlgorithm: algorithm,
            ksenc: key,
            ksmac: ksmac,
            ssc: [UInt8](repeating: 0, count: 8)
        )
        return (reader, chip)
    }

    /// SELECT, the 4-byte header and 160-byte chunks, as the upstream reader reads.
    func readLikeUpstream(_ reader: TagReader) {
        reader.overrideDataAmountToRead(newAmount: 0xA0)
        reader.readsByShortFileIdentifier = false
        reader.readsWholeFirstChunk = false
    }

    /// A TLV file of `totalLength` bytes with a two-byte length (a one-byte one below 128 bytes).
    static func file(tag: UInt8, totalLength: Int) -> [UInt8] {
        let header: [UInt8] = totalLength - 2 < 0x80
            ? [tag, UInt8(totalLength - 2)]
            : [tag, 0x82, UInt8((totalLength - 4) >> 8), UInt8((totalLength - 4) & 0xFF)]
        let bodyLength: Int = totalLength - header.count
        let body: [UInt8] = (0 ..< bodyLength).map { (index: Int) -> UInt8 in
            let value: Int = index * 31 + 17
            return UInt8(value & 0xFF)
        }
        return header + body
    }

    static func tlv(_ tag: [UInt8], _ value: [UInt8]) throws -> [UInt8] {
        try tag + toAsn1Length(value.count) + value
    }

    /// EF.COM for LDS 1.7 and Unicode 4.0.0 listing the given data group tags.
    static func com(declaring tags: [UInt8]) throws -> [UInt8] {
        let version = try tlv([0x5F, 0x01], Array("0107".utf8))
        let unicode = try tlv([0x5F, 0x36], Array("040000".utf8))
        return try tlv([0x60], version + unicode + tlv([0x5C], tags))
    }

    /// DG1 holding the made-up MRZ of the upstream parsing tests.
    static func dataGroup1() throws -> [UInt8] {
        let mrz = "P<GBRTHATCHER<<BOB<<<<<<<<<<<<<<<<<<<<<<<<<<7125143269GBR3906022M1601013<<<<<<<<<<<<<<08"
        return try tlv([0x61], tlv([0x5F, 0x1F], Array(mrz.utf8)))
    }

    /// DG2 holding one ISO/IEC 19794-5 facial record whose JPEG carries `imageBytes` of filler.
    static func dataGroup2(imageBytes: Int) throws -> [UInt8] {
        let recordHeader: [UInt8] = [0x46, 0x41, 0x43, 0x00, 0x30, 0x31, 0x30, 0x00]
            + [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
            + [UInt8](repeating: 0x00, count: 20)
            + [0x01, 0x00, 0x00, 0x10, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
        let jpeg: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]
            + [UInt8](repeating: 0x00, count: imageBytes) + [0xFF, 0xD9]
        let biometricHeader = try tlv([0xA1], tlv([0x80], [0x01, 0x00]))
        let template = try tlv(
            [0x7F, 0x60],
            biometricHeader + tlv([0x5F, 0x2E], recordHeader + jpeg)
        )
        return try tlv([0x75], tlv([0x7F, 0x61], tlv([0x02], [0x01]) + template))
    }

    static func readBinary(length: Int) -> NFCISO7816APDU {
        NFCISO7816APDU(
            instructionClass: 0x00,
            instructionCode: 0xB0,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: Data(),
            expectedResponseLength: length
        )
    }

    func collect(_ body: () async -> Void) async -> [String] {
        let box = MessageBox()
        let observer = NotificationCenter.default.addObserver(
            forName: PassportReaderDiagnostics.notificationName,
            object: nil,
            queue: nil
        ) { notification in
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

/// A session whose read resumes a while after CoreNFC delivered each answer, as when the
/// session's queue is busy.
private final class LateResumingTransport: APDUTransport, @unchecked Sendable {
    let chip: SimulatedChip
    private(set) var lastAnswerDeliveredAt: Date?

    init(chip: SimulatedChip) {
        self.chip = chip
    }

    var historicalBytes: Data? { chip.historicalBytes }

    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        let answer = try await chip.sendCommand(apdu: apdu)
        lastAnswerDeliveredAt = Date()
        try await Task.sleep(nanoseconds: 20_000_000)
        return answer
    }
}

/// A phone that loses every command in transit with the same system error.
private final class ThrowingTransport: APDUTransport {
    let chip: SimulatedChip
    let error: Error

    init(chip: SimulatedChip, error: Error) {
        self.chip = chip
        self.error = error
    }

    var historicalBytes: Data? { chip.historicalBytes }

    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        throw error
    }
}

/// A phone that fails every extended-length APDU in transit, the way CoreNFC reports a frame it
/// cannot carry, before the chip sees it.
private final class FailingTransport: APDUTransport {
    let chip: SimulatedChip
    private(set) var attempts = 0

    init(chip: SimulatedChip) {
        self.chip = chip
    }

    var historicalBytes: Data? { chip.historicalBytes }

    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        attempts += 1
        if apdu.expectedResponseLength > 256 {
            throw NFCReaderError(.readerTransceiveErrorPacketTooLong)
        }
        return try await chip.sendCommand(apdu: apdu)
    }
}
