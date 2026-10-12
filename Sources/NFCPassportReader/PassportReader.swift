//
//  PassportReader.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

#if !os(macOS)
import UIKit
import CoreNFC

@available(iOS 15, *)
public protocol PassportReaderTrackingDelegate: AnyObject {
    func nfcTagDetected()
    func readCardAccess(cardAccess: CardAccess)
    func paceStarted()
    func paceSucceeded()
    func paceFailed()
    func bacStarted()
    func bacSucceeded()
    func bacFailed()
}

@available(iOS 15, *)
extension PassportReaderTrackingDelegate {
    func nfcTagDetected() { /* default implementation */ }
    func readCardAccess(cardAccess: CardAccess) { /* default implementation */ }
    func paceStarted() { /* default implementation */ }
    func paceSucceeded() { /* default implementation */ }
    func paceFailed() { /* default implementation */ }
    func bacStarted() { /* default implementation */ }
    func bacSucceeded() { /* default implementation */ }
    func bacFailed() { /* default implementation */ }
}

@available(iOS 15, *)
public class PassportReader : NSObject {
    private typealias NFCCheckedContinuation = CheckedContinuation<NFCPassportModel, Error>
    private var nfcContinuation: NFCCheckedContinuation?

    public weak var trackingDelegate: PassportReaderTrackingDelegate?
    private var passport : NFCPassportModel = NFCPassportModel()
    
    private var readerSession: NFCTagReaderSession?
    private var currentlyReadingDataGroup : DataGroupId?
    
    var dataGroupsToRead : [DataGroupId] = []
    var readAllDatagroups = false
    private var skipSecureElements = true
    private var skipCA = false
    private var skipPACE = false
    
    // Extended mode is used for reading eMRTD's that support extended length APDUs
    private var useExtendedMode = false

    private var bacHandler : BACHandler?
    private var caHandler : ChipAuthenticationHandler?
    private var paceHandler : PACEHandler?
    private var mrzKey : String = ""
    private var aaChallenge: [UInt8]?
    private var dataAmountToReadOverride : Int? = nil
    
    private var scanCompletedHandler: ((NFCPassportModel?, NFCPassportReaderError?)->())!
    private var nfcViewDisplayMessageHandler: ((NFCViewDisplayMessage) -> String?)?
    private var masterListURL : URL?
    private var shouldNotReportNextReaderSessionInvalidationErrorUserCanceled : Bool = false
    private var sessionStartedAt : Date?
    private var tagConnectedAt : Date?
    private var tagReader : TagReader?

    // By default, Passive Authentication uses the new RFS5652 method to verify the SOD, but can be switched to use
    // the previous OpenSSL CMS verification if necessary
    public var passiveAuthenticationUsesOpenSSL : Bool = false

    /// Lets data groups be read with extended-length APDUs, with responses of up to 1 KB, when
    /// the chip states its buffer sizes in EF.ATR/INFO. Off by default: a phone or chip that
    /// fails an extended APDU ends the session, and no iPhone has been shown to carry one.
    public var extendedLengthReads : Bool = false

    /// Logs one line per APDU on the diagnostic channel: command, offset, lengths, status word,
    /// the round trip and the phone time between commands, never the bytes carried. Off by
    /// default: a large portrait takes about a hundred lines.
    public var apduTrace : Bool = false

    /// Has the reader session deliver its callbacks, APDU answers included, on a serial queue
    /// of its own rather than the main queue, so the host's UI work cannot hold up the chip
    /// exchange while iOS keeps counting the tag time. Session delegate callbacks and the
    /// diagnostic notifications they post then arrive off the main queue. Off by default.
    public var dedicatedSessionQueue : Bool = false

    /// About how long iOS keeps a connected tag before invalidating the session. Apple states no
    /// figure; the session log measures the time left against it.
    static let tagTimeLimit : TimeInterval = 20

    // Data group reads finished in this session, which the length notice estimates the rest by.
    private var transferredAPDUs = 0
    private var transferTime : TimeInterval = 0

    public init( masterListURL: URL? = nil ) {
        super.init()
        
        self.masterListURL = masterListURL
    }
    
    public func setMasterListURL( _ masterListURL : URL ) {
        self.masterListURL = masterListURL
    }
    
    // This function allows you to override the amount of data the TagReader tries to read from the NFC
    // chip. NOTE - this really shouldn't be used for production but is useful for testing as different
    // passports support different data amounts.
    // It appears that the most reliable is 0xA0 (160 chars) but some will support arbitary reads (0xFF or 256)
    public func overrideNFCDataAmountToRead( amount: Int ) {
        dataAmountToReadOverride = amount
    }

    /// Goes back to the reader's own read length after `overrideNFCDataAmountToRead(amount:)`,
    /// which also lets extended-length reads apply again.
    public func clearNFCDataAmountOverride() {
        dataAmountToReadOverride = nil
    }
    
    public func readPassport( mrzKey : String, tags : [DataGroupId] = [], aaChallenge: [UInt8]? = nil, skipSecureElements : Bool = true, skipCA : Bool = false, skipPACE : Bool = false, useExtendedMode : Bool = false, customDisplayMessage : ((NFCViewDisplayMessage) -> String?)? = nil) async throws -> NFCPassportModel {
        
        self.passport = NFCPassportModel()
        self.mrzKey = mrzKey
        self.aaChallenge = aaChallenge
        self.skipCA = skipCA
        self.skipPACE = skipPACE
        self.useExtendedMode = useExtendedMode
        
        self.dataGroupsToRead.removeAll()
        self.dataGroupsToRead.append( contentsOf:tags)
        self.nfcViewDisplayMessageHandler = customDisplayMessage
        self.skipSecureElements = skipSecureElements
        self.currentlyReadingDataGroup = nil
        self.bacHandler = nil
        self.caHandler = nil
        self.paceHandler = nil
        
        // If no tags specified, read all
        if self.dataGroupsToRead.count == 0 {
            // Start off with .COM, will always read (and .SOD but we'll add that after), and then add the others from the COM
            self.dataGroupsToRead.append(contentsOf:[.COM, .SOD] )
            self.readAllDatagroups = true
        } else {
            // We are reading specific datagroups
            self.readAllDatagroups = false
        }
        
        guard NFCNDEFReaderSession.readingAvailable else {
            throw NFCPassportReaderError.NFCNotSupported
        }
        
        let startedAt = Date()
        self.sessionStartedAt = startedAt
        self.tagConnectedAt = nil
        self.tagReader = nil
        let requested = self.readAllDatagroups ? "every data group COM declares" : self.dataGroupsToRead.map { $0.getName() }.joined(separator: ", ")
        Logger.session.info( "Chip session started at \(Self.timestamp(startedAt)) - reading \(requested)" )

        if NFCTagReaderSession.readingAvailable {
            let sessionQueue = dedicatedSessionQueue ? DispatchQueue(label: "AMANFCPassportReader.session") : nil
            readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: sessionQueue)
            
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.requestPresentPassport )
            readerSession?.begin()
        }
        
        return try await withCheckedThrowingContinuation({ (continuation: NFCCheckedContinuation) in
            self.nfcContinuation = continuation
        })
    }
}

@available(iOS 15, *)
extension PassportReader : NFCTagReaderSessionDelegate {
    // MARK: - NFCTagReaderSessionDelegate
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // If necessary, you may perform additional operations on session start.
        // At this point RF polling is enabled.
        Logger.passportReader.debug( "tagReaderSessionDidBecomeActive" )
        Logger.session.info( "\(self.sessionClock()) Reader session active - waiting for a tag" )
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // If necessary, you may handle the error. Note session is no longer valid.
        // You must create a new session to restart RF polling.
        Logger.passportReader.debug( "tagReaderSession:didInvalidateWithError - \(error.localizedDescription)" )
        // The reason the system gives, which a read that already failed on a dead session
        // (NFCError 103) would otherwise never show.
        Logger.session.info( "\(self.sessionClock()) Reader session invalidated - \(diagnosticDescription(of: error))\(self.sinceTagConnected())" )
        self.readerSession?.invalidate()
        self.readerSession = nil

        if let readerError = error as? NFCReaderError, readerError.code == NFCReaderError.readerSessionInvalidationErrorUserCanceled
            && self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled {
            
            self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
        } else {
            var userError = NFCPassportReaderError.UnexpectedError
            if let readerError = error as? NFCReaderError {
                Logger.passportReader.error( "tagReaderSession:didInvalidateWithError - Got NFCReaderError - \(readerError.localizedDescription)" )
                switch (readerError.code) {
                case NFCReaderError.readerSessionInvalidationErrorUserCanceled:
                    Logger.passportReader.error( "     - User cancelled session" )
                    userError = NFCPassportReaderError.UserCanceled
                    self.logSessionEnd( "user cancelled" )
                case NFCReaderError.readerSessionInvalidationErrorSessionTimeout:
                    Logger.passportReader.error("     - Session timeout")
                    userError = NFCPassportReaderError.TimeOutError
                    self.logSessionEnd( "session timeout" )
                default:
                    Logger.passportReader.error( "     - some other error - \(readerError.localizedDescription)" )
                    userError = NFCPassportReaderError.UnexpectedError
                    self.logSessionEnd( "system error - NFCReaderError code \(readerError.errorCode)" )
                }
            } else {
                Logger.passportReader.error( "tagReaderSession:didInvalidateWithError - Received error - \(error.localizedDescription)" )
                self.logSessionEnd( "system error - \(error)" )
            }
            nfcContinuation?.resume(throwing: userError)
            nfcContinuation = nil
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Logger.passportReader.debug( "tagReaderSession:didDetect - found \(tags)" )
        Logger.session.info( "\(self.sessionClock()) Tag detected - \(tags.count) tag\(tags.count == 1 ? "" : "s"), \(tags.map(Self.kind(of:)).joined(separator: ", "))" )
        if tags.count > 1 {
            Logger.passportReader.debug( "tagReaderSession:more than 1 tag detected! - \(tags)" )

            let errorMessage = NFCViewDisplayMessage.error(.MoreThanOneTagFound)
            self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.MoreThanOneTagFound)
            return
        }

        let tag = tags.first!
        var passportTag: NFCISO7816Tag
        switch tags.first! {
        case let .iso7816(tag):
            passportTag = tag
        default:
            Logger.passportReader.debug( "tagReaderSession:invalid tag detected!!!" )

            let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.TagNotValid)
            self.invalidateSession(errorMessage:errorMessage, error: NFCPassportReaderError.TagNotValid)
            return
        }
        
        Task { [passportTag, self] in
            do {
                let connectStartedAt = Date()
                try await session.connect(to: tag)
                
                Logger.passportReader.debug( "tagReaderSession:connected to tag - starting authentication" )
                self.tagConnectedAt = Date()
                Logger.session.info( "\(self.sessionClock()) Tag connected in \(Self.milliseconds(since: connectStartedAt)) ms - application \(passportTag.initialSelectedAID)" )
                self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(0) )
                
                let tagReader = TagReader(tag: passportTag, timesDelivery: self.apduTrace)
                self.tagReader = tagReader
                self.attachDiagnostics(to: tagReader)
                
                if let newAmount = self.dataAmountToReadOverride {
                    tagReader.overrideDataAmountToRead(newAmount: newAmount)
                }
                
                tagReader.progress = { [unowned self] (progress) in
                    if let dgId = self.currentlyReadingDataGroup {
                        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, progress) )
                    } else {
                        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(progress) )
                    }
                }
                
                let passportModel = try await self.startReading( tagReader : tagReader)
                nfcContinuation?.resume(returning: passportModel)
                nfcContinuation = nil

                
            } catch let error as NFCPassportReaderError {
                let errorMessage = NFCViewDisplayMessage.error(error)
                self.invalidateSession(errorMessage: errorMessage, error: error)
            } catch {
                Logger.passportReader.debug( "tagReaderSession:failed to connect to tag - \(error.localizedDescription)" )
                Logger.session.error( "\(self.sessionClock()) Chip session failed on a system error - \(diagnosticDescription(of: error))\(self.sinceTagConnected())" )

                // .readerTransceiveErrorTagResponseError is thrown when a "connection lost" scenario is forced by moving the phone away from the NFC chip
                // .readerTransceiveErrorTagConnectionLost is never thrown for this scenario, but added for the sake of completeness
                if let nfcError = error as? NFCReaderError,
                   nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagResponseError.rawValue ||
                    nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagConnectionLost.rawValue {
                    let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.ConnectionError)
                    self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.ConnectionError)
                } else {
                    let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.Unknown(error))
                    self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.Unknown(error))
                }
            }
        }
    }
    
    func updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage ) {
        self.readerSession?.alertMessage = self.nfcViewDisplayMessageHandler?(alertMessage) ?? alertMessage.description
    }
}

@available(iOS 15, *)
extension PassportReader {
    
    func startReading(tagReader : TagReader) async throws -> NFCPassportModel {
        trackingDelegate?.nfcTagDetected()
        var extendedLengthChecked = false

        if !skipPACE {
            do {
                trackingDelegate?.paceStarted()

                let data: [UInt8]
                do {
                    data = try await tagReader.readCardAccess()
                } catch {
                    Logger.session.info( "\(self.sessionClock()) EF.CardAccess not found - \(error)" )
                    throw error
                }
                Logger.passportReader.debug( "Read CardAccess - data \(binToHexRep(data))" )
                Logger.session.info( "\(self.sessionClock()) EF.CardAccess found (\(data.count) bytes)" )
                let cardAccess = try CardAccess(data)
                passport.cardAccess = cardAccess

                trackingDelegate?.readCardAccess(cardAccess: cardAccess)

                await detectExtendedLength(tagReader: tagReader)
                extendedLengthChecked = true

                Logger.passportReader.info( "Starting Password Authenticated Connection Establishment (PACE)" )
                 
                let paceStartedAt = Date()
                let paceHandler = try PACEHandler( cardAccess: cardAccess, tagReader: tagReader )
                do {
                    try await paceHandler.doPACE(mrzKey: mrzKey )
                } catch {
                    Logger.session.error( "\(self.sessionClock()) PACE failed after \(Self.milliseconds(since: paceStartedAt)) ms - \(error)" )
                    throw error
                }
                passport.PACEStatus = .success
                Logger.passportReader.debug( "PACE Succeeded" )
                Logger.session.info( "\(self.sessionClock()) PACE succeeded in \(Self.milliseconds(since: paceStartedAt)) ms" )

                trackingDelegate?.paceSucceeded()
            } catch {
                trackingDelegate?.paceFailed()

                passport.PACEStatus = .failed
                Logger.passportReader.error( "PACE Failed - falling back to BAC" )
                Logger.session.info( "\(self.sessionClock()) PACE not established (\(error)) - falling back to BAC" )
            }
            
            _ = try await tagReader.selectPassportApplication()
        }
        
        if skipPACE {
            Logger.session.info( "\(self.sessionClock()) PACE skipped at the host's request - BAC only" )
        }
        if !extendedLengthChecked {
            await detectExtendedLengthWithoutPACE(tagReader: tagReader)
        }

        // If either PACE isn't supported, we failed whilst doing PACE or we didn't even attempt it, then fall back to BAC
        if passport.PACEStatus != .success {
            do {
                trackingDelegate?.bacStarted()
                try await doBACAuthentication(tagReader : tagReader)
                trackingDelegate?.bacSucceeded()
            } catch {
                trackingDelegate?.bacFailed()
                throw error
            }
        }
        
        // Now to read the datagroups
        try await readDataGroups(tagReader: tagReader)

        try await doActiveAuthenticationIfNeccessary(tagReader : tagReader)

        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate()
        self.logSessionEnd( "read completed" )

        // If we have a masterlist url set then use that and verify the passport now
        self.passport.verifyPassport(masterListURL: self.masterListURL, useCMSVerification: self.passiveAuthenticationUsesOpenSSL)

        return self.passport
    }
    
    
    func doActiveAuthenticationIfNeccessary( tagReader : TagReader) async throws {
        guard self.passport.activeAuthenticationSupported else {
            Logger.session.info( "\(self.sessionClock()) Active Authentication not supported (no public key in DG15)" )
            return
        }
        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.activeAuthentication)

        Logger.passportReader.info( "Performing Active Authentication" )

        let activeAuthenticationStartedAt = Date()
        let challenge = aaChallenge ?? generateRandomUInt8Array(8)
        Logger.passportReader.debug( "Generated Active Authentication challange - \(binToHexRep(challenge))")
        let response: ResponseAPDU
        do {
            response = try await tagReader.doInternalAuthentication(challenge: challenge, useExtendedMode: useExtendedMode)
        } catch {
            Logger.session.error( "\(self.sessionClock()) Active Authentication failed - the chip rejected INTERNAL AUTHENTICATE - \(error)" )
            throw error
        }
        self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
        Logger.session.info( "\(self.sessionClock()) Active Authentication \(self.passport.activeAuthenticationPassed ? "passed" : "failed - signature not verified") in \(Self.milliseconds(since: activeAuthenticationStartedAt)) ms" )
    }
    

    func doBACAuthentication(tagReader : TagReader) async throws {
        self.currentlyReadingDataGroup = nil

        Logger.passportReader.info( "Starting Basic Access Control (BAC)" )
        
        self.passport.BACStatus = .failed

        let bacStartedAt = Date()
        Logger.session.info( "\(self.sessionClock()) BAC started" )
        self.bacHandler = BACHandler( tagReader: tagReader )
        do {
            try await bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey )
        } catch {
            Logger.session.error( "\(self.sessionClock()) BAC failed after \(Self.milliseconds(since: bacStartedAt)) ms - \(error)" )
            throw error
        }
        Logger.passportReader.info( "Basic Access Control (BAC) - SUCCESS!" )
        Logger.session.info( "\(self.sessionClock()) BAC succeeded in \(Self.milliseconds(since: bacStartedAt)) ms" )

        self.passport.BACStatus = .success
    }

    func readDataGroups( tagReader: TagReader ) async throws {
        
        // Read COM
        var DGsToRead = [DataGroupId]()

        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(.COM, 0) )
        
        if let com = try await readDataGroup(tagReader:tagReader, dgId:.COM) as? COM {
            self.passport.addDataGroup( .COM, dataGroup:com )
            self.addDatagroupsToRead(com: com, to: &DGsToRead)
        }
        
        if DGsToRead.contains( .DG14 ) {
            
            if !skipCA {
                // If we have been explicitly asked to read DG14 and we will be remove it from the list as we are reading it now.
                DGsToRead.removeAll { $0 == .DG14 }

                // Do Chip Authentication
                if let dg14 = try await readDataGroup(tagReader:tagReader, dgId:.DG14) as? DataGroup14 {
                    self.passport.addDataGroup( .DG14, dataGroup:dg14 )
                    let caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
                     
                    if caHandler.isChipAuthenticationSupported {
                        let caStartedAt = Date()
                        let caChipTimeBefore = tagReader.chipTime
                        do {
                            // Do Chip authentication and then continue reading datagroups
                            try await caHandler.doChipAuthentication()
                            self.passport.chipAuthenticationStatus = .success
                            let caChip = Self.milliseconds(tagReader.chipTime - caChipTimeBefore)
                            Logger.session.info( "\(self.sessionClock()) Chip Authentication succeeded in \(Self.milliseconds(since: caStartedAt)) ms, \(caChip) ms of it in APDU round trips" )
                        } catch {
                            Logger.passportReader.info( "Chip Authentication failed - re-establishing BAC")
                            Logger.session.error( "\(self.sessionClock()) Chip Authentication failed after \(Self.milliseconds(since: caStartedAt)) ms - \(error)" )
                            self.passport.chipAuthenticationStatus = .failed
                            
                            // Failed Chip Auth, need to re-establish BAC
                            try await doBACAuthentication(tagReader: tagReader)
                        }
                    } else {
                        Logger.session.info( "\(self.sessionClock()) Chip Authentication not supported (no public key in DG14)" )
                    }
                }
            }
        }

        DGsToRead = Self.readOrder(
            declared: DGsToRead,
            requested: self.readAllDatagroups ? nil : dataGroupsToRead,
            skipSecureElements: self.skipSecureElements
        )
        for dgId in DGsToRead {
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )
            if let dg = try await readDataGroup(tagReader:tagReader, dgId:dgId) {
                self.passport.addDataGroup( dgId, dataGroup:dg )
            }
        }
    }
    
    func readDataGroup( tagReader : TagReader, dgId : DataGroupId ) async throws -> DataGroup?  {

        self.currentlyReadingDataGroup = dgId
        Logger.passportReader.info( "Reading tag - \(dgId.getName())" )
        var readAttempts = 0
        var nfcPassportReaderError: NFCPassportReaderError
        
        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )

        repeat {
            let attemptStartedAt = Date()
            do {
                let response = try await tagReader.readDataGroup(dataGroup:dgId)
                let transfer = tagReader.lastRead.map(Self.transferDescription) ?? ""
                if let read = tagReader.lastRead {
                    transferredAPDUs += read.apdus
                    transferTime += Date().timeIntervalSince(attemptStartedAt)
                }
                Logger.session.info( "\(self.sessionClock()) \(dgId.getName()) read - \(response.count) bytes in \(Self.milliseconds(since: attemptStartedAt)) ms\(transfer) (attempt \(readAttempts + 1))\(self.tagTimeLeft())" )
                let dg = try DataGroupParser().parseDG(data: response)
                return dg
            } catch let error as NFCPassportReaderError {
                Logger.passportReader.error( "TagError reading tag - \(error)" )
                Logger.session.error( "\(self.sessionClock()) \(dgId.getName()) failed after \(Self.milliseconds(since: attemptStartedAt)) ms (attempt \(readAttempts + 1)) - \(error)" )
                nfcPassportReaderError = error

                // OK we had an error - depending on what happened, we may want to try to re-read this
                // E.g. we failed to read the last Datagroup because its protected and we can't
                let errMsg = error.value
                Logger.passportReader.error( "ERROR - \(errMsg)" )
                var redoBAC = false
                if errMsg == "Session invalidated" || errMsg == "Class not supported" || errMsg == "Tag connection lost" || errMsg == "Tag response error / no response" {
                    // Check if we have done Chip Authentication, if so, set it to nil and try to redo BAC
                    if self.caHandler != nil {
                        self.caHandler = nil
                        redoBAC = true
                    } else {
                        // Can't go any more!
                        throw error
                    }
                } else if errMsg == "Security status not satisfied" || errMsg == "File not found" {
                    // Can't read this element as we aren't allowed - remove it and return out so we re-do BAC
                    self.dataGroupsToRead.removeFirst()
                    redoBAC = true
                } else if errMsg == "SM data objects incorrect" || errMsg == "Class not supported" {
                    // Can't read this element security objects now invalid - and return out so we re-do BAC
                    redoBAC = true
                } else if errMsg.hasPrefix( "Wrong length" ) || errMsg.hasPrefix( "End of file" ) {  // Should now handle errors 0x6C xx, and 0x67 0x00
                    // OK passport can't handle max length so drop it down
                    tagReader.reduceDataReadingAmount()
                    redoBAC = true
                } else if errMsg == "UnsupportedDataGroup" {
                    // OK, this DataGroup is not supported, lets skip it
                    Logger.passportReader.debug("Unsupported DataGroup - \(dgId.rawValue)")
                    return nil
                }
                
                if !tagReader.lastResponseKeptSecureMessaging {
                    // The chip answered in plain and has left secure messaging.
                    redoBAC = true
                }
                if redoBAC {
                    // Establish secure messaging again and try again
                    try await reestablishAccessControl(tagReader : tagReader)
                } else {
                    // Some other error lets have another try
                }
            }
            readAttempts += 1
        } while ( readAttempts < 2 )

        // The error will be thrown after n attempts
        throw nfcPassportReaderError
    }

    func invalidateSession(errorMessage: NFCViewDisplayMessage, error: NFCPassportReaderError) {
        // Mark the next 'invalid session' error as not reportable (we're about to cause it by invalidating the
        // session). The real error is reported back with the call to the completed handler
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate(errorMessage: self.nfcViewDisplayMessageHandler?(errorMessage) ?? errorMessage.description)
        self.logSessionEnd( Self.sessionEndReason(for: error) )
        nfcContinuation?.resume(throwing: error)
        nfcContinuation = nil
    }
    
    static func sessionEndReason(for error: NFCPassportReaderError) -> String {
        switch error {
        case .ConnectionError:
            return "tag connection lost"
        case .TimeOutError:
            return "session timeout"
        case .UserCanceled:
            return "user cancelled"
        default:
            return "error - \(error)"
        }
    }

    static func milliseconds(since start: Date) -> Int {
        milliseconds(Date().timeIntervalSince(start))
    }

    static func milliseconds(_ interval: TimeInterval) -> Int {
        Int((interval * 1000).rounded())
    }

    /// ", 14 APDUs, 223-byte chunks, 1650 ms of it in APDU round trips"
    static func transferDescription(_ read: FileReadProgress) -> String {
        var text = ", \(read.apdus) APDUs"
        if read.chunkLength > 0 {
            text += ", \(read.chunkDescription)"
        }
        return text + ", \(milliseconds(read.chipTime)) ms of it in APDU round trips"
    }

    /// Establishes secure messaging again after the chip dropped it: PACE when the session used
    /// PACE, which a PACE-only chip needs, and BAC otherwise or when PACE fails.
    func reestablishAccessControl( tagReader: TagReader ) async throws {
        guard passport.PACEStatus == .success, let cardAccess = passport.cardAccess else {
            try await doBACAuthentication(tagReader: tagReader)
            return
        }
        let startedAt = Date()
        Logger.session.info( "\(self.sessionClock()) Establishing PACE again" )
        do {
            tagReader.secureMessaging = nil
            _ = try await tagReader.selectMasterFile()
            let paceHandler = try PACEHandler(cardAccess: cardAccess, tagReader: tagReader)
            try await paceHandler.doPACE(mrzKey: mrzKey)
            _ = try await tagReader.selectPassportApplication()
            Logger.session.info( "\(self.sessionClock()) PACE established again in \(Self.milliseconds(since: startedAt)) ms" )
        } catch {
            Logger.session.error( "\(self.sessionClock()) PACE not established again (\(error)) - falling back to BAC" )
            try await doBACAuthentication(tagReader: tagReader)
        }
    }

    static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }

    /// Time since the session started, prefixed to every milestone so a shared log reads as a
    /// timeline, followed once the tag is connected by the time since then (T+), which is what
    /// iOS limits.
    func sessionClock() -> String {
        guard let sessionStartedAt else { return "+?s" }
        let now = Date()
        var clock = String(format: "+%.3fs", now.timeIntervalSince(sessionStartedAt))
        if let tagConnectedAt {
            clock += String(format: " T+%.3fs", now.timeIntervalSince(tagConnectedAt))
        }
        return clock
    }

    /// Wires the session log to a tag reader: the per-APDU trace when `apduTrace` is on, and the
    /// notice that gives each data group's length as soon as its first bytes arrive.
    func attachDiagnostics( to tagReader: TagReader ) {
        transferredAPDUs = 0
        transferTime = 0
        tagReader.fileLengthObserver = { [weak self] read, chunkLength in
            self?.logFileLength(read, chunkLength: chunkLength)
        }
        tagReader.apduObserver = apduTrace
            ? { [weak self] trace in
                guard let self else { return }
                Logger.apdu.info( "\(self.sessionClock()) \(trace.summary)" )
            }
            : nil
        Logger.session.info( "\(self.sessionClock()) Reader options - APDU trace \(self.apduTrace ? "on" : "off"), extended-length reads \(self.extendedLengthReads ? "on" : "off"), read length \(self.dataAmountToReadOverride.map { "\($0) bytes (host override)" } ?? "\(tagReader.maxDataLengthToRead) bytes"), PACE \(self.skipPACE ? "skipped" : "on"), Chip Authentication \(self.skipCA ? "skipped" : "on"), session callbacks on \(self.dedicatedSessionQueue ? "a dedicated queue" : "the main queue")" )
    }

    /// "DG2 is 23456 bytes - 105 more APDUs in 223-byte chunks, ~14.2 s at 135 ms per APDU so
    /// far; 9.6 s of the ~20 s tag time left". A session that dies mid-file still leaves the
    /// file's size and what it would have needed.
    func logFileLength( _ read: FileReadProgress, chunkLength: Int ) {
        guard let dgId = currentlyReadingDataGroup, let length = read.length else { return }
        let remaining = max(length - read.bytesRead, 0)
        let apdus = chunkLength > 0 ? (remaining + chunkLength - 1) / chunkLength : 0
        var line = "\(sessionClock()) \(dgId.getName()) is \(length) bytes - \(apdus) more APDUs in \(chunkLength)-byte chunks"
        if transferredAPDUs > 0 {
            let perAPDU = transferTime / Double(transferredAPDUs)
            line += String(format: ", ~%.1f s at %d ms per APDU so far", Double(apdus) * perAPDU, Self.milliseconds(perAPDU))
        }
        Logger.session.info( line + self.tagTimeLeft() )
    }

    /// "; 9.6 s of the ~20 s tag time left", empty before the tag connects.
    func tagTimeLeft() -> String {
        guard let tagConnectedAt else { return "" }
        let left = Self.tagTimeLimit - Date().timeIntervalSince(tagConnectedAt)
        guard left >= 0 else {
            return String(format: "; %.1f s past the ~%.0f s tag time", -left, Self.tagTimeLimit)
        }
        return String(format: "; %.1f s of the ~%.0f s tag time left", left, Self.tagTimeLimit)
    }

    /// With PACE skipped, or on a chip without EF.CardAccess, nothing reaches the point where the
    /// extended-length check otherwise runs. EF.ATR/INFO sits in the master file like EF.CardAccess, so the check
    /// selects it first and the eMRTD application again afterwards; with extended-length reads
    /// off it sends nothing and only reports the historical bytes.
    func detectExtendedLengthWithoutPACE( tagReader: TagReader ) async {
        guard extendedLengthReads else {
            await detectExtendedLength(tagReader: tagReader)
            return
        }
        _ = try? await tagReader.selectMasterFile()
        await detectExtendedLength(tagReader: tagReader)
        _ = try? await tagReader.selectPassportApplication()
    }

    static func kind( of tag: NFCTag ) -> String {
        switch tag {
        case .iso7816: return "ISO 7816"
        case .feliCa: return "FeliCa"
        case .iso15693: return "ISO 15693"
        case .miFare: return "MIFARE"
        @unknown default: return "unknown"
        }
    }

    func logSessionEnd(_ reason: String) {
        let endedAt = Date()
        var detail = sinceTagConnected()
        let snapshot = tagReader?.sessionSnapshot()
        if let read = snapshot?.currentRead {
            detail += " - reading \(currentlyReadingDataGroup?.getName() ?? binToHexRep(read.fileId)): \(read.bytesRead) of \(read.length.map(String.init) ?? "?") bytes after \(read.apdus) APDUs"
            if read.chunkLength > 0 {
                detail += ", \(read.chunkDescription)"
            }
        }
        if let snapshot {
            detail += " - \(snapshot.apduCount) APDUs in the session"
        }
        Logger.session.info( "\(self.sessionClock()) Chip session ended at \(Self.timestamp(endedAt)) - \(reason)\(detail)" )
    }

    /// Time since the tag connected, which the system limits separately from the session.
    func sinceTagConnected() -> String {
        guard let tagConnectedAt else { return "" }
        return String(format: " (%.3fs after the tag connected)", Date().timeIntervalSince(tagConnectedAt))
    }

    /// Reports what the chip states about extended-length APDUs and, when `extendedLengthReads`
    /// is on, lets data group reads use them if the chip states its buffer sizes. Never fails the
    /// session: a chip that says nothing is read in short APDUs as before. EF.ATR/INFO is only
    /// read when it can change how data groups are read.
    func detectExtendedLength( tagReader: TagReader ) async {
        var info = ExtendedLengthInfo()
        var historicalBytes = "none"
        if let bytes = tagReader.tag.historicalBytes, !bytes.isEmpty {
            historicalBytes = bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
            info.indicatedByHistoricalBytes = ExtendedLengthInfo.extendedLengthBit(historicalBytes: [UInt8](bytes))
        }
        guard extendedLengthReads else {
            let capability = ExtendedLengthInfo.describe(info.indicatedByHistoricalBytes)
            Logger.session.info( "\(self.sessionClock()) Extended length - historical bytes \(historicalBytes) (\(capability)); extended-length reads off - data groups read in \(tagReader.maxDataLengthToRead)-byte chunks" )
            return
        }
        var atrInfo = "not present"
        do {
            if let bytes = try await tagReader.readATRInfo() {
                atrInfo = "\(bytes.count) bytes"
                let parsed = ExtendedLengthInfo.parse(atrInfo: bytes)
                info.indicatedByATRInfo = parsed.indicatedByATRInfo
                info.maxCommandLength = parsed.maxCommandLength
                info.maxResponseLength = parsed.maxResponseLength
            }
        } catch {
            atrInfo = "not read - \(error)"
        }
        let reads = tagReader.enableExtendedLengthReads(info: info)
            ? "data groups read with extended length, responses up to \(tagReader.extendedResponseLimit ?? 0) bytes"
            : "data groups read in \(tagReader.maxDataLengthToRead)-byte chunks"
        Logger.session.info( "\(self.sessionClock()) Extended length - historical bytes \(historicalBytes), EF.ATR/INFO \(atrInfo); \(info.summary) - \(reads)" )
    }

    /// The order data groups are read in after COM and Chip Authentication. A read asking for
    /// specific groups gets them in the order it asked, restricted to what COM declares plus SOD,
    /// so the caller decides what is in hand first. A read of everything takes SOD and then COM's order.
    static func readOrder(
        declared: [DataGroupId],
        requested: [DataGroupId]?,
        skipSecureElements: Bool
    ) -> [DataGroupId] {
        var available = declared
        if skipSecureElements {
            available = available.filter { $0 != .DG3 && $0 != .DG4 }
        }
        guard let requested else { return available }
        var order: [DataGroupId] = []
        for dgId in requested where available.contains(dgId) && !order.contains(dgId) {
            order.append(dgId)
        }
        return order
    }

    internal func addDatagroupsToRead(com: COM, to DGsToRead: inout [DataGroupId]) {
        DGsToRead += com.dataGroupsPresent.compactMap { DataGroupId.getIDFromName(name:$0) }
        DGsToRead.removeAll { $0 == .COM }
        
        // SOD should not be present in COM, but just in case we check before adding it so its not read twice
        if !DGsToRead.contains(.SOD) { DGsToRead.insert(.SOD, at: 0) }
    }
}
#endif
