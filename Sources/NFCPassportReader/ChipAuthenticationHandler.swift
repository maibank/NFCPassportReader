//
//  ChipAuthenticationHandler.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation
import OSLog
import OpenSSL

#if !os(macOS)
import CoreNFC
import CryptoKit

@available(iOS 15, *)
class ChipAuthenticationHandler {
    
    private static let NO_PACE_KEY_REFERENCE : UInt8 = 0x00
    private static let ENC_MODE : UInt8 = 0x1
    private static let MAC_MODE : UInt8 = 0x2
    private static let PACE_MODE : UInt8 = 0x3

    private static let COMMAND_CHAINING_CHUNK_SIZE = 224

    var tagReader : TagReader?
    var gaSegments = [[UInt8]]()
    
    var chipAuthInfos = [Int:ChipAuthenticationInfo]()
    var chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo]()
    
    var isChipAuthenticationSupported : Bool = false
    
    public init(dg14 : DataGroup14, tagReader: TagReader) {
        self.tagReader = tagReader
        
        for secInfo in dg14.securityInfos {
            if let cai = secInfo as? ChipAuthenticationInfo {
                let keyId = cai.getKeyId()
                chipAuthInfos[keyId] = cai
            } else if let capki = secInfo as? ChipAuthenticationPublicKeyInfo {
                chipAuthPublicKeyInfos.append(capki)
            }
        }
        
        if chipAuthPublicKeyInfos.count > 0 {
            isChipAuthenticationSupported = true
        }
    }

    public func doChipAuthentication() async throws  {
                
        Logger.chipAuth.info( "Performing Chip Authentication - number of public keys found - \(self.chipAuthPublicKeyInfos.count)" )
        guard isChipAuthenticationSupported else {
            throw NFCPassportReaderError.NotYetSupported( "ChipAuthentication not supported" )
        }
        
        var success = false
        for pubKey in chipAuthPublicKeyInfos {
            do {
                success = try await self.doChipAuthentication( with: pubKey)
                if success {
                    break
                }
            } catch {
                // try next key
            }
        }
        
        if !success {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
    }
    
    /// Performs the key agreement part of Chip Authentication using an ephemeral public key that was generated
    /// elsewhere (e.g. by a backend) rather than generating our own.
    /// As we don't have the matching private key, we can't derive the new Secure Messaging keys, so after this
    /// only APDUs that have been protected by the owner of the ephemeral key can be sent to the passport
    /// - Parameter ephemeralKeys: the available ephemeral keys - the one matching the domain parameters of the passports public key is used
    /// - Returns: details of the Chip Authentication that was run
    public func doChipAuthentication( using ephemeralKeys : [ChipAuthenticationEphemeralKey] ) async throws -> ChipAuthenticationResult {

        Logger.chipAuth.info( "Performing Chip Authentication with external ephemeral key - number of public keys found - \(self.chipAuthPublicKeyInfos.count)" )
        guard isChipAuthenticationSupported else {
            throw NFCPassportReaderError.NotYetSupported( "ChipAuthentication not supported" )
        }

        for chipAuthPublicKeyInfo in chipAuthPublicKeyInfos {
            let keyId = chipAuthPublicKeyInfo.keyId
            guard let oid = chipAuthInfos[keyId ?? 0]?.oid ?? inferOID( fromPublicKeyOID:chipAuthPublicKeyInfo.oid),
                  let parameterId = OpenSSLUtils.getStandardisedDomainParameterId(from: chipAuthPublicKeyInfo.pubKey),
                  let ephemeralKey = ephemeralKeys.first(where: { $0.parameterId == parameterId }) else {
                // try next key
                continue
            }

            try await sendPublicKey(oid: oid, keyId: keyId, keyData: ephemeralKey.publicKey)
            Logger.chipAuth.debug( "Public Key successfully sent to passport!" )

            // The passport has now switched to the new session keys (which we can't derive)
            tagReader?.secureMessaging = nil

            return ChipAuthenticationResult(keyRef: ephemeralKey.keyRef, protocolOid: oid, keyId: keyId)
        }

        throw NFCPassportReaderError.InvalidDataPassed( "No ephemeral key matches the domain parameters of the passports Chip Authentication public key" )
    }

    private func doChipAuthentication( with chipAuthPublicKeyInfo : ChipAuthenticationPublicKeyInfo ) async throws -> Bool {
        
        // So it turns out that some passports don't have ChipAuthInfo items.
        // So if we do have a ChipAuthInfo the we take the keyId (if present) and OID from there,
        // BUT if we don't then we will try to infer the OID from the public key
        let keyId = chipAuthPublicKeyInfo.keyId
        let chipAuthInfoOID : String
        if let chipAuthInfo = chipAuthInfos[keyId ?? 0] {
            chipAuthInfoOID = chipAuthInfo.oid
        } else {
            if let oid = inferOID( fromPublicKeyOID:chipAuthPublicKeyInfo.oid) {
                chipAuthInfoOID = oid
            } else {
                return false
            }
        }
        
        try await self.doCA( keyId: keyId, encryptionDetailsOID: chipAuthInfoOID, publicKey: chipAuthPublicKeyInfo.pubKey )
        return true
    }
    
    /// Infer OID from public key type - Best guess seems to be to use 3DES_CBC_CBC for both ECDH and DH keys
    /// Apparently works for French passports
    private func inferOID(fromPublicKeyOID: String ) -> String? {
        if fromPublicKeyOID == SecurityInfo.ID_PK_ECDH_OID {
            Logger.chipAuth.warning("No ChipAuthenticationInfo - guessing its id-CA-ECDH-3DES-CBC-CBC");
            return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID
        } else if fromPublicKeyOID == SecurityInfo.ID_PK_DH_OID {
            Logger.chipAuth.warning("No ChipAuthenticationInfo - guessing its id-CA-DH-3DES-CBC-CBC");
            return SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID
        }
        
        Logger.chipAuth.warning("No ChipAuthenticationInfo and unsupported ChipAuthenticationPublicKeyInfo public key OID \(fromPublicKeyOID)")
        return nil;
    }
    
    private func doCA( keyId: Int?, encryptionDetailsOID oid: String, publicKey: OpaquePointer) async throws {
        
        // Generate Ephemeral Keypair from parameters from DG14 Public key
        // This should work for both EC and DH keys
        var ephemeralKeyPair : OpaquePointer? = nil
        let pctx = EVP_PKEY_CTX_new(publicKey, nil)
        EVP_PKEY_keygen_init(pctx)
        EVP_PKEY_keygen(pctx, &ephemeralKeyPair)
        EVP_PKEY_CTX_free(pctx)
        
        // Send the public key to the passport
        guard let keyData = OpenSSLUtils.getPublicKeyData(from: ephemeralKeyPair!) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data from public key" )
        }
        try await sendPublicKey(oid: oid, keyId: keyId, keyData: keyData)
            
        Logger.chipAuth.debug( "Public Key successfully sent to passport!" )
        
        // Use our ephemeral private key and the passports public key to generate a shared secret
        // (the passport with do the same thing with their private key and our public key)
        let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair:ephemeralKeyPair!, publicKey:publicKey)
        
        // Now try to restart Secure Messaging using the new shared secret and
        try restartSecureMessaging( oid : oid, sharedSecret : sharedSecret, maxTranceiveLength : 1, shouldCheckMAC : true)
    }
    
    private func sendPublicKey(oid : String, keyId : Int?, keyData : [UInt8]) async throws {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)

        if cipherAlg.hasPrefix("DESede") {
        
            var idData : [UInt8] = []
            if let keyId = keyId {
                idData = intToBytes( val:keyId, removePadding:true)
                idData = wrapDO( b:0x84, arr:idData)
            }
            let wrappedKeyData = wrapDO( b:0x91, arr:keyData)
            _ = try await self.tagReader?.sendMSEKAT(keyData: Data(wrappedKeyData), idData: Data(idData))
        } else if cipherAlg.hasPrefix("AES") {
            _ = try await self.tagReader?.sendMSESetATIntAuth(oid: oid, keyId: keyId)
            let data = wrapDO(b: 0x80, arr:keyData)
            gaSegments = self.chunk(data: data, segmentSize: ChipAuthenticationHandler.COMMAND_CHAINING_CHUNK_SIZE )
            try await self.handleGeneralAuthentication()
        } else {
            throw NFCPassportReaderError.InvalidDataPassed("Cipher Algorithm \(cipherAlg) not supported")
        }
    }
    
    private func handleGeneralAuthentication() async throws {
        repeat {
            // Pull next segment from list
            let segment = gaSegments.removeFirst()
            let isLast = gaSegments.isEmpty
        
            // send it
            _ = try await self.tagReader?.sendGeneralAuthenticate(data: segment, isLast: isLast)
        } while ( !gaSegments.isEmpty )
    }
        
    private func restartSecureMessaging( oid : String, sharedSecret : [UInt8], maxTranceiveLength : Int, shouldCheckMAC : Bool) throws  {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid)
        
        // Start secure messaging.
        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let ksMac = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        
        let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
        if (cipherAlg.hasPrefix("DESede")) {
            Logger.chipAuth.info( "Restarting secure messaging using DESede encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .DES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else if (cipherAlg.hasPrefix("AES")) {
            Logger.chipAuth.info( "Restarting secure messaging using AES encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else {
            Logger.chipAuth.error( "Not restarting secure messaging as unsupported cipher algorithm requested - \(cipherAlg)")
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm \(cipherAlg)" )
        }
    }
    
    
    func inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation( cipherAlg : String, keyLength : Int) throws -> String {
        if cipherAlg == "DESede" || cipherAlg == "AES-128" {
            return "SHA1"
        }
        if cipherAlg == "AES" && keyLength == 128 {
            return "SHA1"
        }
        if cipherAlg == "AES-256" || cipherAlg ==  "AES-192" {
            return "SHA256"
        }
        if cipherAlg == "AES" && (keyLength == 192 || keyLength == 256) {
            return "SHA256"
        }
        
        throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm or key length")
    }
    
    /// Chunks up a byte array into a number of segments of the given size,
    /// and a final segment if there is a remainder.
    /// - Parameter segmentSize the number of bytes per segment
    /// - Parameter data the data to be partitioned
    /// - Parameter a list with the segments
    func chunk( data : [UInt8], segmentSize: Int ) -> [[UInt8]] {
        return stride(from: 0, to: data.count, by: segmentSize).map {
            Array(data[$0 ..< Swift.min($0 + segmentSize, data.count)])
        }
    }
}

#endif
