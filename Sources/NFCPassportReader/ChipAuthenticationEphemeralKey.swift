//
//  ChipAuthenticationEphemeralKey.swift
//  NFCPassportReader
//

import Foundation

/// An ephemeral Chip Authentication public key that was generated outside of the app (e.g. by a backend).
/// The matching private key never reaches the device, so only the key's owner can derive the
/// Secure Messaging keys and verify that the chip is genuine
@available(iOS 13, macOS 10.15, *)
public struct ChipAuthenticationEphemeralKey {
    /// Reference used by the key's owner to find the matching private key
    public let keyRef : String
    /// ICAO 9303-11 standardised domain parameter id (e.g. 13 for brainpoolP256r1)
    public let parameterId : Int
    /// Raw public key - uncompressed EC point (04 || X || Y) for ECDH, public value for DH
    public let publicKey : [UInt8]

    public init(keyRef: String, parameterId: Int, publicKey: [UInt8]) {
        self.keyRef = keyRef
        self.parameterId = parameterId
        self.publicKey = publicKey
    }
}

/// Details of the Chip Authentication that was run with a `ChipAuthenticationEphemeralKey`
@available(iOS 13, macOS 10.15, *)
public struct ChipAuthenticationResult {
    /// Reference of the ephemeral key that was sent to the chip
    public let keyRef : String
    /// OID of the Chip Authentication protocol that was run (e.g. 0.4.0.127.0.7.2.2.3.2.2)
    public let protocolOid : String
    /// Id of the chip's Chip Authentication key in DG14 (only set if DG14 specifies one)
    public let keyId : Int?
}
