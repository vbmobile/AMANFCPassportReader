//
//  DataGroup2.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation
import OSLog

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
public class DataGroup2 : DataGroup {
    enum FaceImageFormat: String {
        case jpeg = "JPEG"
        case jp2 = "JPEG 2000 (JP2)"
        case jpeg2000Codestream = "JPEG 2000 (J2K codestream)"

        /// Any JPEG start of image followed by a marker: JFIF (APP0), Exif (APP1),
        /// Adobe (APP14) or no application segment at all.
        static let jpegSignature: [UInt8] = [0xFF, 0xD8, 0xFF]
        /// SOC followed by SIZ, the first two markers of every JPEG 2000 codestream.
        static let jpeg2000CodestreamSignature: [UInt8] = [0xFF, 0x4F, 0xFF, 0x51]
        /// The type of the JPEG 2000 signature box, which opens every JP2 file.
        static let jp2SignatureBoxType: [UInt8] = [0x6A, 0x50, 0x20, 0x20]

        static func detect(_ bytes: ArraySlice<UInt8>) -> FaceImageFormat? {
            if bytes.starts(with: jpegSignature) {
                return .jpeg
            }
            if bytes.starts(with: jpeg2000CodestreamSignature) {
                return .jpeg2000Codestream
            }
            if bytes.count >= 8, bytes.dropFirst(4).starts(with: jp2SignatureBoxType) {
                return .jp2
            }
            return nil
        }

        /// Where the first image signature sits, for records that do not follow the
        /// ISO/IEC 19794-5 layout this parser walks.
        static func firstImageOffset(in bytes: [UInt8], from start: Int) -> Int? {
            guard start < bytes.count else { return nil }
            for index in start ..< bytes.count where detect(bytes[index...]) != nil {
                return index
            }
            return nil
        }
    }
    
    
    public private(set) var nrImages : Int = 0
    public private(set) var versionNumber : Int = 0
    public private(set) var lengthOfRecord : Int = 0
    public private(set) var numberOfFacialImages : Int = 0
    public private(set) var facialRecordDataLength : Int = 0
    public private(set) var nrFeaturePoints : Int = 0
    public private(set) var gender : Int = 0
    public private(set) var eyeColor : Int = 0
    public private(set) var hairColor : Int = 0
    public private(set) var featureMask : Int = 0
    public private(set) var expression : Int = 0
    public private(set) var poseAngle : Int = 0
    public private(set) var poseAngleUncertainty : Int = 0
    public private(set) var faceImageType : Int = 0
    public private(set) var imageDataType : Int = 0
    public private(set) var imageWidth : Int = 0
    public private(set) var imageHeight : Int = 0
    public private(set) var imageColorSpace : Int = 0
    public private(set) var sourceType : Int = 0
    public private(set) var deviceType : Int = 0
    public private(set) var quality : Int = 0
    public private(set) var imageData : [UInt8] = []
    
    public override var datagroupType: DataGroupId { .DG2 }
    
#if !os(macOS)
    func getImage() -> UIImage? {
        if imageData.count == 0 {
            return nil
        }
        
        let image = UIImage(data:Data(imageData) )
        return image
    }
#endif
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x7F61)
        _ = try getNextLength()
        
        // Tag should be 0x02
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x02)
        nrImages = try Int(getNextValue()[0])
        
        // Next tag is 0x7F60
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x7F60)
        _ = try getNextLength()
        
        // Next tag is 0xA1 (Biometric Header Template) - don't care about this
        tag = try getNextTag()
        try verifyTag(tag, equals: 0xA1)
        _ = try getNextValue()
        
        // Now we get to the good stuff - next tag is either 5F2E or 7F2E
        tag = try getNextTag()
        try verifyTag(tag, oneOf: [0x5F2E, 0x7F2E])
        let value = try getNextValue()
        
        
        try parseISO19794_5( data:value )
    }
    
    func parseISO19794_5( data : [UInt8] ) throws {
        // Validate header - 'F', 'A' 'C' 0x00 - 0x46414300
        guard data.starts(with: [0x46, 0x41, 0x43, 0x00]), data.count >= DataGroup2.facialRecordFixedLength else {
            // Not a record this parser can walk (an ISO/IEC 39794-5 record, or a
            // truncated one): take the image from wherever its signature starts.
            Logger.passportReader.warning( "DG2 facial record is not ISO/IEC 19794-5 - header \(DataGroup2.headerDescription(data[...]))" )
            guard let imageOffset = FaceImageFormat.firstImageOffset(in: data, from: 0) else {
                throw NFCPassportReaderError.InvalidResponse(
                    dataGroupId: datagroupType,
                    expectedTag: 0x46,
                    actualTag: Int(data.first ?? 0)
                )
            }
            imageData = try extractFaceImageData(from: data, offset: imageOffset)
            return
        }
        
        var offset = 4
        versionNumber = binToInt(data[offset..<offset+4])
        offset += 4
        lengthOfRecord = binToInt(data[offset..<offset+4])
        offset += 4
        numberOfFacialImages = binToInt(data[offset..<offset+2])
        offset += 2
        
        facialRecordDataLength = binToInt(data[offset..<offset+4])
        offset += 4

        nrFeaturePoints = binToInt(data[offset..<offset+2])
        offset += 2
        gender = binToInt(data[offset..<offset+1])
        offset += 1
        eyeColor = binToInt(data[offset..<offset+1])
        offset += 1
        hairColor = binToInt(data[offset..<offset+1])
        offset += 1
        featureMask = binToInt(data[offset..<offset+3])
        offset += 3
        expression = binToInt(data[offset..<offset+2])
        offset += 2
        poseAngle = binToInt(data[offset..<offset+3])
        offset += 3
        poseAngleUncertainty = binToInt(data[offset..<offset+3])
        offset += 3
        
        // Features (not handled). There shouldn't be any but if for some reason there were,
        // then we are going to skip over them
        // The Feature block is 8 bytes
        offset += nrFeaturePoints * 8
        guard data.count >= offset + 12 else {
            throw NFCPassportReaderError.InvalidASN1Value
        }
        
        faceImageType = binToInt(data[offset..<offset+1])
        offset += 1
        imageDataType = binToInt(data[offset..<offset+1])
        offset += 1
        imageWidth = binToInt(data[offset..<offset+2])
        offset += 2
        imageHeight = binToInt(data[offset..<offset+2])
        offset += 2
        imageColorSpace = binToInt(data[offset..<offset+1])
        offset += 1
        sourceType = binToInt(data[offset..<offset+1])
        offset += 1
        deviceType = binToInt(data[offset..<offset+2])
        offset += 2
        quality = binToInt(data[offset..<offset+2])
        offset += 2
        
        
        // Make sure that the image data at least has a valid header
        // Either JPG or JPEG2000
        
        
        imageData = try extractFaceImageData(
            from: data,
            offset: offset
        )
    }
    
    private func extractFaceImageData(from data: [UInt8], offset: Int) throws -> [UInt8] {
        let remaining = offset < data.count ? Array(data[offset...]) : []
        let header = DataGroup2.headerDescription(remaining[...])

        var format = FaceImageFormat.detect(remaining[...])
        var imageStart = offset
        if format == nil, let found = FaceImageFormat.firstImageOffset(in: data, from: offset) {
            // Some records carry padding or extra fields between the header and the image.
            format = FaceImageFormat.detect(data[found...])
            imageStart = found
            Logger.passportReader.warning( "DG2 image signature found \(found - offset) bytes past the record header - header \(header)" )
        }

        guard let format else {
            Logger.passportReader.error( "DG2 image format not recognised - header \(header), \(remaining.count) bytes" )
            throw NFCPassportReaderError.UnknownImageFormat
        }

        let image = Array(data[imageStart...])
        let extracted: [UInt8]
        switch format {
            case .jpeg:
                // The end-of-image marker trims trailing padding; without one the image runs to the end.
                extracted = Array(image[..<(findJPEGEnd(in: image) ?? image.count)])
            case .jpeg2000Codestream:
                extracted = Array(image[..<(findJPEG2000CodestreamEnd(in: image) ?? image.count)])
            case .jp2:
                extracted = (try? extractJP2BoxData(from: data, offset: imageStart, maxEnd: data.count)) ?? image
        }
        Logger.passportReader.info( "DG2 image \(format.rawValue), \(extracted.count) of \(image.count) bytes - header \(DataGroup2.headerDescription(image[...]))" )
        return extracted
    }

    /// ISO/IEC 19794-5 facial record header, facial information and image information
    /// blocks, up to the image data when no feature points are present.
    static let facialRecordFixedLength = 46

    /// The first 16 bytes in hex: enough to identify the image format, too short to carry any picture.
    static func headerDescription(_ bytes: ArraySlice<UInt8>) -> String {
        bytes.isEmpty ? "(empty)" : bytes.prefix(16).map { String(format: "%02X", $0) }.joined(separator: " ")
    }
    
    private func extractJP2BoxData(from data: [UInt8], offset: Int, maxEnd: Int) throws -> [UInt8] {
        var p = offset
        
        while p + 8 <= maxEnd {
            let boxStart = p
            let length = binToInt(data[p..<p + 4])
            p += 4
            
            let boxType = Array(data[p..<p + 4])
            p += 4
            
            let boxEnd: Int
            
            if length == 0 {
                // Box extends to end of containing data
                boxEnd = maxEnd
            } else if length == 1 {
                // XLBox: 64-bit box length
                guard p + 8 <= maxEnd else {
                    throw NFCPassportReaderError.UnknownImageFormat
                }
                
                let largeLength = binToInt64(data[p..<p + 8])
                p += 8
                
                guard largeLength >= 16 else {
                    throw NFCPassportReaderError.UnknownImageFormat
                }
                
                boxEnd = boxStart + Int(largeLength)
            } else {
                guard length >= 8 else {
                    throw NFCPassportReaderError.UnknownImageFormat
                }
                
                boxEnd = boxStart + length
            }
            
            guard boxEnd <= maxEnd else {
                throw NFCPassportReaderError.UnknownImageFormat
            }
            
            p = boxEnd
            
            // jp2c box: this is the codestream box.
            // Once we have consumed it, the JP2 image is complete.
            if boxType == [0x6A, 0x70, 0x32, 0x63] {
                return Array(data[offset..<boxEnd])
            }
        }
        
        throw NFCPassportReaderError.UnknownImageFormat
    }
    
    private func findJPEGEnd(in data: [UInt8]) -> Int? {
        guard data.count >= 2 else { return nil }
        
        // Go backwards to find end of file marker
        
        for i in stride(from: data.count - 2, through: 0, by: -1) {
            if data[i] == 0xFF && data[i + 1] == 0xD9 {
                return i + 2
            }
        }
        
        return nil
    }
    
    private func findJPEG2000CodestreamEnd(in data: [UInt8]) -> Int? {
        // JPEG2000 codestream EOC marker
        return findJPEGEnd(in: data)
    }
    
    private func binToInt64(_ slice: ArraySlice<UInt8>) -> UInt64 {
        var value: UInt64 = 0
        
        for byte in slice {
            value = (value << 8) | UInt64(byte)
        }
        
        return value
    }
}
