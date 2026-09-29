//
//  TagHandler.swift
//  NFCTest
//
//  Created by Andy Qua on 09/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

#if !os(macOS)
import CoreNFC

/// The APDU exchange with the chip, so the reading logic can also run against a simulated chip.
protocol APDUTransport {
    var historicalBytes: Data? { get }
    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8)
}

@available(iOS 15, *)
struct ISO7816TagTransport: APDUTransport {
    let tag: NFCISO7816Tag

    var historicalBytes: Data? { tag.historicalBytes }

    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        try await tag.sendCommand(apdu: apdu)
    }
}

/// How one file read went: what the session milestones report, and what a failed
/// session reports about the read it was in.
struct FileReadProgress {
    let fileId: [UInt8]
    var length: Int?
    var bytesRead = 0
    var apdus = 0
    var chunkLength = 0
    var extendedLength = false

    var chunkDescription: String {
        "\(chunkLength)-byte \(extendedLength ? "extended-length " : "")chunks"
    }
}

@available(iOS 15, *)
public class TagReader {
    /// Plaintext bytes per READ BINARY when the chip states no buffer sizes. 223 is the largest
    /// amount whose secure messaging response still fits a short APDU (256 bytes) under AES:
    /// 224 bytes of padded cipher text, the DO'87' and DO'99' headers and the 8-byte MAC.
    static let shortReadLength = 0xDF
    /// The length reads step down to when a chip refuses 223 bytes.
    static let fallbackReadLength = 0xA0
    /// Extended-length responses are kept to this size whatever larger buffer the chip states:
    /// responses of about 1.7 KB have been lost between iPhones and chips, and 1 KB already cuts
    /// the round trips of a large DG2 by more than four.
    static let maxExtendedResponseLength = 1024

    var tag : APDUTransport
    var secureMessaging : SecureMessaging?
    var maxDataLengthToRead : Int = TagReader.shortReadLength

    /// The response APDU size reads may use with extended length, set only when the chip states
    /// its buffer sizes (ICAO 9303-10 forbids extended READ BINARY otherwise).
    private(set) var extendedResponseLimit : Int?
    private var dataAmountOverridden = false

    /// Every APDU exchanged with the chip, GET RESPONSE included.
    private(set) var apduCount = 0
    /// The file being read, while it is read.
    private(set) var currentRead : FileReadProgress?
    /// The last file read in full.
    private(set) var lastRead : FileReadProgress?

    var progress : ((Int)->())?

    init( tag: NFCISO7816Tag ) {
        self.tag = ISO7816TagTransport(tag: tag)
    }

    init( transport: APDUTransport ) {
        self.tag = transport
    }

    func overrideDataAmountToRead( newAmount : Int ) {
        maxDataLengthToRead = newAmount
        dataAmountOverridden = true
        extendedResponseLimit = nil
    }

    func reduceDataReadingAmount() {
        extendedResponseLimit = nil
        if maxDataLengthToRead > TagReader.fallbackReadLength {
            maxDataLengthToRead = TagReader.fallbackReadLength
        }
    }

    /// Lets reads use extended length up to the response size the chip states, capped at
    /// `maxExtendedResponseLength`. Returns whether reads will use it.
    @discardableResult
    func enableExtendedLengthReads( info: ExtendedLengthInfo ) -> Bool {
        guard !dataAmountOverridden, let limit = info.usableResponseLimit else { return false }
        extendedResponseLimit = min(limit, TagReader.maxExtendedResponseLength)
        return true
    }

    /// Plaintext bytes that fit a secure messaging response of `responseLimit` bytes (status
    /// word included): the cipher text, padded to the block size with at least one byte, plus
    /// DO'87' (tag, up to three length bytes, padding indicator), DO'99' (4) and DO'8E' (10).
    static func readLength( responseLimit: Int, blockSize: Int ) -> Int {
        let cipherText = (responseLimit - 2 - 10 - 4 - 5) / blockSize * blockSize
        return cipherText - 1
    }


    func readDataGroup( dataGroup: DataGroupId ) async throws -> [UInt8]  {
        guard let tag = dataGroup.getFileIDTag() else {
            throw NFCPassportReaderError.UnsupportedDataGroup
        }
        
        return try await selectFileAndRead(tag: tag )
    }
    
    func getChallenge() async throws -> ResponseAPDU{
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x84, p1Parameter: 0, p2Parameter: 0, data: Data(), expectedResponseLength: 8)
        
        return try await send( cmd: cmd )
    }
    
    func doInternalAuthentication( challenge: [UInt8], useExtendedMode: Bool ) async throws -> ResponseAPDU {
        let randNonce = Data(challenge)
        
        var responseLength = 256
        if useExtendedMode {
            responseLength = 65535
        }
        
        let cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x88, p1Parameter: 0, p2Parameter: 0, data: randNonce, expectedResponseLength: responseLength)

        return try await send( cmd: cmd, useExtendedMode: useExtendedMode )
    }

    func doMutualAuthentication( cmdData : Data ) async throws -> ResponseAPDU{
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x82, p1Parameter: 0, p2Parameter: 0, data: cmdData, expectedResponseLength: 256)

        return try await send( cmd: cmd )
    }
    
    /// The MSE KAT APDU, see EAC 1.11 spec, Section B.1.
    /// This command is sent in the "DESede" case.
    /// - Parameter keyData key data object (tag 0x91)
    /// - Parameter idData key id data object (tag 0x84), can be null
    /// - Parameter completed the complete handler - returns the success response or an error
    func sendMSEKAT( keyData : Data, idData: Data? ) async throws -> ResponseAPDU {
        
        var data = keyData
        if let idData = idData {
            data += idData
        }
        
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA6, data: data, expectedResponseLength: 256)
        
        return try await send( cmd: cmd )
    }
    
    /// The  MSE Set AT for Chip Authentication.
    /// This command is the first command that is sent in the "AES" case.
    /// For Chip Authentication. We prefix 0x80 for OID and 0x84 for keyId.
    ///
    /// NOTE THIS IS CURRENTLY UNTESTED
    /// - Parameter oid the OID
    /// - Parameter keyId the keyId or {@code null}
    /// - Parameter completed the complete handler - returns the success response or an error
    func sendMSESetATIntAuth( oid: String, keyId: Int? ) async throws -> ResponseAPDU {
        
        let cmd : NFCISO7816APDU
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        
        if let keyId = keyId, keyId != 0 {
            let keyIdBytes = wrapDO(b:0x84, arr:intToBytes(val:keyId, removePadding: true))
            let data = oidBytes + keyIdBytes
            
            cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: 256)
            
        } else {
            cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0x41, p2Parameter: 0xA4, data: Data(oidBytes), expectedResponseLength: 256)
        }
        
        return try await send( cmd: cmd )
    }
    
    func sendMSESetATMutualAuth( oid: String, keyType: UInt8 ) async throws -> ResponseAPDU {
        
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        let keyTypeBytes = wrapDO( b: 0x83, arr:[keyType])
        
        let data = oidBytes + keyTypeBytes
            
        let cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x22, p1Parameter: 0xC1, p2Parameter: 0xA4, data: Data(data), expectedResponseLength: -1)
        
        return try await send( cmd: cmd )
    }
    

    /// Sends a General Authenticate command.
    /// This command is the second command that is sent in the "AES" case.
    /// - Parameter data data to be sent, without the {@code 0x7C} prefix (this method will add it)
    /// - Parameter lengthExpected the expected length defaults to 256
    /// - Parameter isLast indicates whether this is the last command in the chain
    /// - Parameter completed the complete handler - returns the dynamic authentication data without the {@code 0x7C} prefix (this method will remove it) or an error
    func sendGeneralAuthenticate( data : [UInt8], lengthExpected : Int = 256, isLast: Bool) async throws -> ResponseAPDU {

        let wrappedData = wrapDO(b:0x7C, arr:data)
        let commandData = Data(wrappedData)
            
         // NOTE: Support of Protocol Response Data is CONDITIONAL:
         // It MUST be provided for version 2 but MUST NOT be provided for version 1.
         // So, we are expecting 0x7C (= tag), 0x00 (= length) here.
        
        // 0x10 is class command chaining
        let instructionClass : UInt8 = isLast ? 0x00 : 0x10
        let INS_BSI_GENERAL_AUTHENTICATE : UInt8 = 0x86
        
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: instructionClass, instructionCode: INS_BSI_GENERAL_AUTHENTICATE, p1Parameter: 0x00, p2Parameter: 0x00, data: commandData, expectedResponseLength: lengthExpected)
        var response : ResponseAPDU
        do {
            response = try await send( cmd: cmd )
            response.data = try unwrapDO( tag:0x7c, wrappedData:response.data)
        } catch {
            // If wrong length error
            if case NFCPassportReaderError.ResponseError(_, let sw1, let sw2) = error,
               sw1 == 0x67, sw2 == 0x00 {
                
                // Resend
                let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: instructionClass, instructionCode: INS_BSI_GENERAL_AUTHENTICATE, p1Parameter: 0x00, p2Parameter: 0x00, data: commandData, expectedResponseLength: 256)
                response = try await send( cmd: cmd )
                response.data = try unwrapDO( tag:0x7c, wrappedData:response.data)
            } else {
                throw error
            }
        }
        return response
    }
    

    func selectFileAndRead( tag: [UInt8]) async throws -> [UInt8] {
        let apdusBefore = apduCount
        currentRead = FileReadProgress(fileId: tag)
        func track(_ update: (inout FileReadProgress) -> Void) {
            guard var read = currentRead else { return }
            update(&read)
            read.apdus = apduCount - apdusBefore
            currentRead = read
        }

        var resp = try await selectFile(tag: tag )
        track { _ in }

        // Read first 4 bytes of header to see how big the data structure is
        guard let readHeaderCmd = NFCISO7816APDU(data:Data([0x00, 0xB0, 0x00, 0x00, 0x00, 0x00,0x04])) else {
            throw NFCPassportReaderError.UnexpectedError
        }
        resp = try await self.send( cmd: readHeaderCmd )
        track { _ in }
        guard resp.data.count >= 2 else {
            throw NFCPassportReaderError.CannotDecodeASN1Length
        }

        // Header looks like:  <tag><length of data><nextTag> e.g.60145F01 -
        // the total length is the 2nd value plus the two header 2 bytes
        // We've read 4 bytes so we now need to read the remaining bytes from offset 4
        let (len, o) = try asn1Length([UInt8](resp.data[1...]))
        var remaining = Int(len)
        var amountRead = o + 1
        guard resp.data.count >= amountRead else {
            throw NFCPassportReaderError.CannotDecodeASN1Length
        }

        var data = [UInt8](resp.data[..<amountRead])
        track {
            $0.length = amountRead + remaining
            $0.bytesRead = amountRead
        }

        Logger.tagReader.debug( "TagReader - Number of data bytes to read - \(remaining)" )

        while remaining > 0 {
            let (chunkLength, extended) = currentChunkLength()
            var readAmount = chunkLength
            if chunkLength != 256 && remaining < chunkLength {
                readAmount = remaining
            }

            self.progress?( Int(Float(amountRead) / Float(remaining+amountRead ) * 100))
            let offset = intToBin(amountRead, pad:4)

            Logger.tagReader.debug( "TagReader - data bytes remaining: \(remaining), will read : \(readAmount)" )
            let cmd = NFCISO7816APDU(
                instructionClass: 00,
                instructionCode: 0xB0,
                p1Parameter: offset[0],
                p2Parameter: offset[1],
                data: Data(),
                expectedResponseLength: readAmount
            )
            track {
                $0.chunkLength = chunkLength
                $0.extendedLength = extended
            }
            do {
                resp = try await self.send( cmd: cmd, useExtendedMode: extended )
            } catch let error as NFCPassportReaderError {
                track { _ in }
                guard stepDownReadLength(after: error, offset: amountRead) else { throw error }
                continue
            }

            Logger.tagReader.debug( "TagReader - got resp - \(binToHexRep(resp.data, asArray: true)), sw1 : \(resp.sw1), sw2 : \(resp.sw2)" )
            guard !resp.data.isEmpty else {
                // Asking again for the same bytes would only repeat this until the session ends.
                Logger.tagReader.error( "TagReader - the chip returned no data at offset \(amountRead) with \(remaining) bytes left" )
                throw NFCPassportReaderError.ResponseError( "No data returned", resp.sw1, resp.sw2 )
            }
            data += resp.data

            remaining -= resp.data.count
            amountRead += resp.data.count
            track { $0.bytesRead = amountRead }
            Logger.tagReader.debug( "TagReader - Amount of data left to read - \(remaining)" )
        }

        lastRead = currentRead
        currentRead = nil
        return data
    }

    /// Reads EF.ATR/INFO (2F01 in the master file), which states the chip's extended-length
    /// buffer sizes. Nil when the chip has no such file or does not let it be read. Runs in
    /// plain mode with the master file selected, so right after EF.CardAccess.
    func readATRInfo() async throws -> [UInt8]? {
        guard secureMessaging == nil else { return nil }
        do {
            _ = try await selectFile(tag: [0x2F, 0x01])
        } catch let error as NFCPassportReaderError {
            Logger.tagReader.debug( "TagReader - EF.ATR/INFO not selected - \(error)" )
            return nil
        }

        // The file is a list of data objects rather than one, so no header gives its length:
        // ask for up to 256 bytes and take the end-of-file warning as the end of the file.
        var expected = 256
        for _ in 0 ..< 2 {
            let cmd = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xB0, p1Parameter: 0x00, p2Parameter: 0x00, data: Data(), expectedResponseLength: expected)
            apduCount += 1
            let (data, sw1, sw2) = try await tag.sendCommand(apdu: cmd)
            if (sw1 == 0x90 && sw2 == 0x00) || (sw1 == 0x62 && sw2 == 0x82) {
                return data.isEmpty ? nil : [UInt8](data)
            }
            guard sw1 == 0x6C, sw2 > 0 else { return nil }
            expected = Int(sw2)
        }
        return nil
    }

    /// The length the next READ BINARY asks for, and whether it needs extended length.
    func currentChunkLength() -> (Int, Bool) {
        if let limit = extendedResponseLimit, let sm = secureMessaging {
            let length = TagReader.readLength(responseLimit: limit, blockSize: sm.blockSize)
            if length > sm.maxShortResponseLength {
                return (length, true)
            }
        }
        return (maxDataLengthToRead, false)
    }

    /// After a chip refuses a read length (6700 or 6Cxx) the same offset is read again with the
    /// next smaller length: extended, then 223, then 160 bytes. False when nothing smaller is left.
    func stepDownReadLength( after error: NFCPassportReaderError, offset: Int ) -> Bool {
        guard case let .ResponseError(_, sw1, sw2) = error, (sw1 == 0x67 && sw2 == 0x00) || sw1 == 0x6C else {
            return false
        }
        let refused = currentChunkLength().0
        let status = String(format: "%02X%02X", sw1, sw2)
        if extendedResponseLimit != nil {
            extendedResponseLimit = nil
        } else if maxDataLengthToRead > TagReader.fallbackReadLength {
            maxDataLengthToRead = TagReader.fallbackReadLength
        } else {
            return false
        }
        let next = currentChunkLength().0
        Logger.tagReader.info( "Chip refused a \(refused)-byte read at offset \(offset) (\(status)) - reading on in \(next)-byte chunks" )
        return true
    }


    func readCardAccess() async throws -> [UInt8]{
        // Info provided by @smulu
        // By default NFCISO7816Tag requirers a list of ISO/IEC 7816 applets (AIDs). Upon discovery of NFC tag the first found applet from this list is automatically selected (and you have no way of changing this).
        // This is a problem for PACE protocol becaues it requires reading parameters from file EF.CardAccess which lies outside of eMRTD applet (AID: A0000002471001) in the master file.
        
        // Now, the ICAO 9303 standard does specify command for selecting master file by sending SELECT APDU with P1=0x00, P2=0x0C and empty data field (see part 10 page 8). But after some testing I found out this command doesn't work on some passports (European passports) and although receiving success (sw=9000) from passport the master file is not selected.
        
        // After a bit of researching standard ISO/IEC 7816 I found there is an alternative SELECT command for selecting master file. The command doesn't differ much from the command specified in ICAO 9303 doc with only difference that data field is set to: 0x3F00. See section 6.11.3 of ISO/IEC 7816-4.
        // By executing above SELECT command (with data=0x3F00) master file should be selected and you should be able to read EF.CardAccess from passport.
        
        // First select master file
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x00, p2Parameter: 0x0C, data: Data([0x3f,0x00]), expectedResponseLength: -1)
        
        _ = try await send( cmd: cmd)
            
        // Now read EC.CardAccess
        let data = try await self.selectFileAndRead(tag: [0x01,0x1C])
        return data
    }
    
    func selectPassportApplication() async throws -> ResponseAPDU {
        // Finally reselect the eMRTD application so the rest of the reading works as normal
        Logger.tagReader.debug( "Re-selecting eMRTD Application" )
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x04, p2Parameter: 0x0C, data: Data([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]), expectedResponseLength: -1)
        
        let response = try await self.send( cmd: cmd)
        return response
    }
    
    func selectFile( tag: [UInt8] ) async throws -> ResponseAPDU {
        
        let data : [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02] + tag
        let cmd = NFCISO7816APDU(data:Data(data))!
        
        return try await send( cmd: cmd )
    }

    func send( cmd: NFCISO7816APDU, useExtendedMode : Bool = false ) async throws -> ResponseAPDU {
        Logger.tagReader.debug( "TagReader - sending \(cmd)" )
        var toSend = cmd
        if let sm = secureMessaging {
            toSend = try sm.protect(apdu:cmd, useExtendedMode: useExtendedMode)
            Logger.tagReader.debug("TagReader - [SM] \(toSend)" )
        }
        
        apduCount += 1
        var (data, sw1, sw2) = try await tag.sendCommand(apdu: toSend)
        Logger.tagReader.debug( "TagReader - Received response, size \(data.count)b" )

        // Some commands may have bigger response than expected. Read the whole response using INS 0xC0 (GET RESPONSE).
        while (sw1 == 0x61) {
            let getResponseCmd = NFCISO7816APDU(instructionClass: 0x0, instructionCode: 0xC0, p1Parameter: 0x0, p2Parameter: 0x0, data: Data(), expectedResponseLength: Int(sw2))
            let nextSegment: Data
            // Overwrite sw1 and sw2.
            apduCount += 1
            (nextSegment, sw1, sw2) = try await tag.sendCommand(apdu: getResponseCmd)
            Logger.tagReader.debug("Read remaining data. Accumulated: \(data.count + nextSegment.count)b. Last batch \(nextSegment.count)b. Still remaining: \(sw2)b")
            data += nextSegment
        }

        var rep = ResponseAPDU(data: [UInt8](data), sw1: sw1, sw2: sw2)
        
        if let sm = self.secureMessaging {
            rep = try sm.unprotect(rapdu:rep)
            Logger.tagReader.debug("\(String(format:"TagReader [SM - unprotected] \(binToHexRep(rep.data, asArray:true)), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2))" )
        } else {
            Logger.tagReader.debug("\(String(format:"TagReader [unprotected] \(binToHexRep(rep.data, asArray:true)), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2))" )
            
        }
        
        // A READ BINARY answered with anything but 9000 carries no file data. The upstream check
        // lets every status ending in 00 through (6700 wrong length, 6B00 offset beyond the file),
        // and the read loop then asks for the same bytes until the session ends. Other commands
        // keep that check until they are verified against chips with the stricter one.
        let isReadBinary = cmd.instructionCode == 0xB0
        let failed = isReadBinary ? !(rep.sw1 == 0x90 && rep.sw2 == 0x00) : (rep.sw1 != 0x90 && rep.sw2 != 0x00)
        if failed {
            Logger.tagReader.error( "Error reading tag: sw1 - 0x\(binToHexRep(rep.sw1)), sw2 - 0x\(binToHexRep(rep.sw2))" )
            let tagError: NFCPassportReaderError
            if (rep.sw1 == 0x63 && rep.sw2 == 0x00) {
                tagError = NFCPassportReaderError.InvalidMRZKey
            } else {
                let errorMsg = self.decodeError(sw1: rep.sw1, sw2: rep.sw2)
                Logger.tagReader.error( "reason: \(errorMsg)" )
                tagError = NFCPassportReaderError.ResponseError( errorMsg, rep.sw1, rep.sw2 )
            }
            throw tagError
        }

        return rep
    }

    private func decodeError( sw1: UInt8, sw2:UInt8 ) -> String {

        let errors : [UInt8 : [UInt8:String]] = [
            0x62: [0x00:"No information given",
                   0x81:"Part of returned data may be corrupted",
                   0x82:"End of file/record reached before reading Le bytes",
                   0x83:"Selected file invalidated",
                   0x84:"FCI not formatted according to ISO7816-4 section 5.1.5"],
            
            0x63: [0x81:"File filled up by the last write",
                   0x82:"Card Key not supported",
                   0x83:"Reader Key not supported",
                   0x84:"Plain transmission not supported",
                   0x85:"Secured Transmission not supported",
                   0x86:"Volatile memory not available",
                   0x87:"Non Volatile memory not available",
                   0x88:"Key number not valid",
                   0x89:"Key length is not correct",
                   0xC:"Counter provided by X (valued from 0 to 15) (exact meaning depending on the command)"],
            0x65: [0x00:"No information given",
                   0x81:"Memory failure"],
            0x67: [0x00:"Wrong length"],
            0x68: [0x00:"No information given",
                   0x81:"Logical channel not supported",
                   0x82:"Secure messaging not supported",
                   0x83:"Last command of the chain expected",
                   0x84:"Command chaining not supported"],
            0x69: [0x00:"No information given",
                   0x81:"Command incompatible with file structure",
                   0x82:"Security status not satisfied",
                   0x83:"Authentication method blocked",
                   0x84:"Referenced data invalidated",
                   0x85:"Conditions of use not satisfied",
                   0x86:"Command not allowed (no current EF)",
                   0x87:"Expected SM data objects missing",
                   0x88:"SM data objects incorrect"],
            0x6A: [0x00:"No information given",
                   0x80:"Incorrect parameters in the data field",
                   0x81:"Function not supported",
                   0x82:"File not found",
                   0x83:"Record not found",
                   0x84:"Not enough memory space in the file",
                   0x85:"Lc inconsistent with TLV structure",
                   0x86:"Incorrect parameters P1-P2",
                   0x87:"Lc inconsistent with P1-P2",
                   0x88:"Referenced data not found"],
            0x6B: [0x00:"Wrong parameter(s) P1-P2]"],
            0x6D: [0x00:"Instruction code not supported or invalid"],
            0x6E: [0x00:"Class not supported"],
            0x6F: [0x00:"No precise diagnosis"],
            0x90: [0x00:"Success"] //No further qualification
        ]
        
        // Special cases - where sw2 isn't an error but contains a value
        if sw1 == 0x61 {
            return "SW2 indicates the number of response bytes still available - (\(sw2) bytes still available)"
        } else if sw1 == 0x64 {
            return "State of non-volatile memory unchanged (SW2=00, other values are RFU)"
        } else if sw1 == 0x6C {
            return "Wrong length Le: SW2 indicates the exact length - (exact length :\(sw2))"
        }

        if let dict = errors[sw1], let errorMsg = dict[sw2] {
            return errorMsg
        }
        
        return "Unknown error - sw1: 0x\(binToHexRep(sw1)), sw2 - 0x\(binToHexRep(sw2)) "
    }
}

#endif
