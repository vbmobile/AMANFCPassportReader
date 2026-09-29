//
//  ExtendedLengthInfo.swift
//

import Foundation

/// What a chip says about extended-length APDUs (ISO/IEC 7816-4, ICAO 9303-10 section 3.6.4):
/// the card capabilities bit in its historical bytes or in EF.ATR/INFO, and the buffer sizes
/// EF.ATR/INFO states in DO'7F66'. ICAO 9303-10 forbids an extended READ BINARY unless the
/// buffer sizes are stated, so the bit alone is reported and never acted on.
struct ExtendedLengthInfo: Equatable {
    var indicatedByHistoricalBytes: Bool?
    var indicatedByATRInfo: Bool?
    var maxCommandLength: Int?
    var maxResponseLength: Int?

    /// Smallest response APDU size worth reading with extended length: a short response
    /// already carries 256 bytes and the status word.
    static let minimumUsefulResponseLength = 259

    /// The response size reads may use, nil when extended length must not be used.
    var usableResponseLimit: Int? {
        guard let maxResponseLength, maxResponseLength >= Self.minimumUsefulResponseLength else { return nil }
        // A protected extended READ BINARY command is 23 bytes.
        if let maxCommandLength, maxCommandLength < 23 { return nil }
        return maxResponseLength
    }

    var summary: String {
        var parts: [String] = []
        if let maxCommandLength, let maxResponseLength {
            parts.append("EF.ATR/INFO buffers - command \(maxCommandLength), response \(maxResponseLength) bytes")
        } else {
            parts.append("no buffer sizes stated")
        }
        parts.append("card capabilities: historical bytes \(Self.describe(indicatedByHistoricalBytes)), EF.ATR/INFO \(Self.describe(indicatedByATRInfo))")
        return parts.joined(separator: "; ")
    }

    /// Reads the extended-length bit of the card capabilities in the historical bytes of a
    /// type A chip's ATS. Nil when they carry no card capabilities.
    static func extendedLengthBit(historicalBytes: [UInt8]) -> Bool? {
        guard let category = historicalBytes.first else { return nil }
        var objects: ArraySlice<UInt8>
        switch category {
        case 0x80:
            objects = historicalBytes.dropFirst()
        case 0x00:
            // The last three bytes are the status indicator.
            guard historicalBytes.count >= 4 else { return nil }
            objects = historicalBytes.dropFirst().dropLast(3)
        default:
            return nil
        }
        while let header = objects.first {
            let tag = header >> 4
            let length = Int(header & 0x0F)
            let value = objects.dropFirst().prefix(length)
            guard value.count == length else { return nil }
            if tag == 0x7 {
                return capabilitiesBit(Array(value))
            }
            objects = objects.dropFirst(1 + length)
        }
        return nil
    }

    /// Parses EF.ATR/INFO, a list of BER-TLV data objects: DO'47' card capabilities and
    /// DO'7F66' holding two integers, the largest command and response APDUs in bytes.
    static func parse(atrInfo bytes: [UInt8]) -> ExtendedLengthInfo {
        var info = ExtendedLengthInfo()
        for (tag, value) in dataObjects(bytes) {
            switch tag {
            case 0x47:
                info.indicatedByATRInfo = capabilitiesBit(value)
            case 0x7F66:
                let integers = dataObjects(value).filter { $0.0 == 0x02 }.map { $0.1.reduce(0) { $0 << 8 | Int($1) } }
                if integers.count >= 2 {
                    info.maxCommandLength = integers[0]
                    info.maxResponseLength = integers[1]
                }
            default:
                break
            }
        }
        return info
    }
}

// MARK: - Private
private extension ExtendedLengthInfo {
    static func describe(_ bit: Bool?) -> String {
        switch bit {
        case .some(true): return "extended length"
        case .some(false): return "short only"
        case .none: return "not stated"
        }
    }

    /// The third software function byte, b7: extended Lc and Le fields.
    static func capabilitiesBit(_ capabilities: [UInt8]) -> Bool? {
        guard capabilities.count >= 3 else { return nil }
        return capabilities[2] & 0x40 != 0
    }

    static func length(at index: Int, in bytes: [UInt8]) -> (Int, Int)? {
        try? asn1Length([UInt8](bytes[index...]))
    }

    /// Top-level BER-TLV objects; stops at the first malformed one. Bytes 00 and FF
    /// between objects are padding.
    static func dataObjects(_ bytes: [UInt8]) -> [(Int, [UInt8])] {
        var objects: [(Int, [UInt8])] = []
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x00 || bytes[index] == 0xFF {
                index += 1
                continue
            }
            var tag = Int(bytes[index])
            index += 1
            if tag & 0x1F == 0x1F {
                while index < bytes.count {
                    let next = bytes[index]
                    tag = tag << 8 | Int(next)
                    index += 1
                    if next & 0x80 == 0 { break }
                }
            }
            guard index < bytes.count, case let (length, lengthSize)? = Self.length(at: index, in: bytes) else { break }
            index += lengthSize
            guard index + length <= bytes.count else { break }
            objects.append((tag, [UInt8](bytes[index ..< index + length])))
            index += length
        }
        return objects
    }
}
