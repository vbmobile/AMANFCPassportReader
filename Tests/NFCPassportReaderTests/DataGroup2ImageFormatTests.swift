//
//  DataGroup2ImageFormatTests.swift
//

import Foundation
import XCTest

@testable import AMANFCPassportReader

/// DG2 portraits come in more shapes than the JFIF JPEG and strictly terminated
/// JPEG 2000 the parser used to accept. Rejecting one fails the whole chip read,
/// so every shape an issuer ships has to parse. The images here are synthetic:
/// a signature and a few bytes, never a real picture.
final class DataGroup2ImageFormatTests: XCTestCase {
    func testJPEGWithJFIFHeaderIsAccepted() throws {
        let image: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0xFF, 0xD9]

        let dg2 = try parse(image: image)

        XCTAssertEqual(dg2.imageData, image)
    }

    func testJPEGWithExifHeaderIsAccepted() throws {
        let image: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x08, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0xFF, 0xD9]

        let dg2 = try parse(image: image)

        XCTAssertEqual(dg2.imageData, image)
    }

    func testJPEGStartingWithAQuantisationTableIsAccepted() throws {
        let image: [UInt8] = [0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0xFF, 0xD9]

        let dg2 = try parse(image: image)

        XCTAssertEqual(dg2.imageData, image)
    }

    func testJPEGPaddingAfterTheEndOfImageMarkerIsTrimmed() throws {
        let image: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x02, 0xFF, 0xD9]

        let dg2 = try parse(image: image + [0x00, 0x00, 0x00, 0x00])

        XCTAssertEqual(dg2.imageData, image)
    }

    func testJPEGWithoutAnEndOfImageMarkerKeepsEveryByte() throws {
        let image: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x12, 0x34]

        let dg2 = try parse(image: image)

        XCTAssertEqual(dg2.imageData, image)
    }

    func testJPEG2000CodestreamIsAccepted() throws {
        let image: [UInt8] = [0xFF, 0x4F, 0xFF, 0x51, 0x00, 0x2F, 0x00, 0x00, 0xFF, 0xD9]

        let dg2 = try parse(image: image)

        XCTAssertEqual(dg2.imageData, image)
    }

    func testJPEG2000CodestreamWithoutAnEndMarkerKeepsEveryByte() throws {
        let image: [UInt8] = [0xFF, 0x4F, 0xFF, 0x51, 0x00, 0x2F, 0x00, 0x00, 0x01, 0x02]

        let dg2 = try parse(image: image)

        XCTAssertEqual(dg2.imageData, image)
    }

    func testJP2FileIsCutAfterItsCodestreamBox() throws {
        let image = jp2SignatureBox + jp2Box(type: "jp2c", payload: [0xFF, 0x4F, 0xFF, 0xD9])

        let dg2 = try parse(image: image + [0x00, 0x00])

        XCTAssertEqual(dg2.imageData, image)
    }

    func testJP2FileWithoutACodestreamBoxKeepsEveryByte() throws {
        let image = jp2SignatureBox + jp2Box(type: "ftyp", payload: [0x6A, 0x70, 0x32, 0x20])

        let dg2 = try parse(image: image)

        XCTAssertEqual(dg2.imageData, image)
    }

    func testImageAfterUnexpectedBytesPastTheRecordHeaderIsFound() throws {
        let image: [UInt8] = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02, 0xFF, 0xD9]

        let dg2 = try parse(image: [0x00, 0x00, 0x00] + image)

        XCTAssertEqual(dg2.imageData, image)
    }

    func testRecordThatIsNotISO19794IsSearchedForItsImage() throws {
        let image: [UInt8] = [0xFF, 0x4F, 0xFF, 0x51, 0x00, 0x2F, 0xFF, 0xD9]
        let record: [UInt8] = [0xA1, 0x0C, 0x80, 0x02, 0x00, 0x01, 0x04, 0x06] + image

        let dg2 = try DataGroup2(dataGroup2(facialRecord: record))

        XCTAssertEqual(dg2.imageData, image)
    }

    func testUnknownImageFormatIsRejected() throws {
        let image: [UInt8] = [0x42, 0x4D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

        XCTAssertThrowsError(try parse(image: image)) { error in
            guard case NFCPassportReaderError.UnknownImageFormat = error else {
                return XCTFail("Expected UnknownImageFormat, got \(error)")
            }
        }
    }

    func testDetectedFormatNamesEveryAcceptedSignature() {
        let jpeg: [UInt8] = [0xFF, 0xD8, 0xFF, 0xEE]
        let codestream: [UInt8] = [0xFF, 0x4F, 0xFF, 0x51]
        let bareStartOfImage: [UInt8] = [0xFF, 0xD8, 0x00, 0x00]

        XCTAssertEqual(DataGroup2.FaceImageFormat.detect(jpeg[...]), .jpeg)
        XCTAssertEqual(DataGroup2.FaceImageFormat.detect(codestream[...]), .jpeg2000Codestream)
        XCTAssertEqual(DataGroup2.FaceImageFormat.detect(jp2SignatureBox[...]), .jp2)
        XCTAssertNil(DataGroup2.FaceImageFormat.detect(bareStartOfImage[...]))
    }

    func testHeaderDescriptionIsCappedAtSixteenBytes() {
        let bytes = [UInt8](0 ..< 40)
        let empty: [UInt8] = []

        XCTAssertEqual(DataGroup2.headerDescription(bytes[...]), "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        XCTAssertEqual(DataGroup2.headerDescription(empty[...]), "(empty)")
    }
}

// MARK: - Private
private extension DataGroup2ImageFormatTests {
    var jp2SignatureBox: [UInt8] {
        [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A]
    }

    func jp2Box(type: String, payload: [UInt8]) -> [UInt8] {
        let length = UInt32(8 + payload.count)
        return withUnsafeBytes(of: length.bigEndian, Array.init) + Array(type.utf8) + payload
    }

    func parse(image: [UInt8]) throws -> DataGroup2 {
        try DataGroup2(dataGroup2(facialRecord: facialRecordHeader + image))
    }

    /// An ISO/IEC 19794-5 facial record header with one image and no feature points, up to the image data.
    var facialRecordHeader: [UInt8] {
        [0x46, 0x41, 0x43, 0x00, 0x30, 0x31, 0x30, 0x00]  // "FAC", version "010"
            + [0x00, 0x00, 0x00, 0x00]  // length of record
            + [0x00, 0x01]  // number of facial images
            + [0x00, 0x00, 0x00, 0x00]  // facial record data length
            + [0x00, 0x00]  // number of feature points
            + [0x00, 0x00, 0x00]  // gender, eye colour, hair colour
            + [0x00, 0x00, 0x00]  // feature mask
            + [0x00, 0x00]  // expression
            + [0x00, 0x00, 0x00]  // pose angle
            + [0x00, 0x00, 0x00]  // pose angle uncertainty
            + [0x01, 0x00]  // face image type, image data type
            + [0x00, 0x10, 0x00, 0x10]  // width, height
            + [0x01, 0x00, 0x00, 0x00, 0x00, 0x00]  // colour space, source type, device type, quality
    }

    func tlv(_ tag: [UInt8], _ value: [UInt8]) throws -> [UInt8] {
        try tag + toAsn1Length(value.count) + value
    }

    func dataGroup2(facialRecord: [UInt8]) throws -> [UInt8] {
        let biometricHeader = try tlv([0xA1], tlv([0x80], [0x01, 0x00]))
        let biometricDataBlock = try tlv([0x5F, 0x2E], facialRecord)
        let template = try tlv([0x7F, 0x60], biometricHeader + biometricDataBlock)
        let group = try tlv([0x7F, 0x61], tlv([0x02], [0x01]) + template)
        return try tlv([0x75], group)
    }
}
