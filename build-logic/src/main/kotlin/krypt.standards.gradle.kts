/*
 * Copyright 2026 Davils
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.time.Duration

plugins {
    id("krypt.base")
}

kreate {
    assurance {
        standards {
            enabled = true
            reviewEvery = Duration.ofDays(365)

            inventory {
                includes.set(setOf("*.md", "krypt-*/src/**"))
            }

            rfc(1421) {
                note = "PEM with the Proc-Type and DEK-Info headers of OpenSSL: krypt recognises the legacy " +
                    "encryption and refuses it."
            }
            rfc(2104) {
                note = "HMAC: the MACs of krypt-primitive and the base of HKDF, computed by JCA or WebCrypto."
            }
            rfc(3161) {
                note = "Time-stamp tokens: a signed manifest of krypt-stream carries them as opaque attachments."
            }
            rfc(3394) {
                note = "AES key wrap: the key wraps of krypt-primitive."
            }
            rfc(4231) {
                note = "The HMAC-SHA-2 test vectors the MAC tests check against."
            }
            rfc(4648) {
                note = "Base64 and base64url: strict, constant-time codecs of krypt-core that refuse every " +
                    "non-canonical input."
            }
            rfc(5280) {
                note = "X.509: the encoding of times in DER and the profile the certificates of krypt follow."
            }
            rfc(5869) {
                note = "HKDF: implemented over HMAC in common code, so both targets derive alike."
            }
            rfc(6960) {
                note = "OCSP: requests, strict responses, their verification against the issuer or a delegated " +
                    "responder, the revocation checker of path validation and the logic of a responder."
            }
            rfc(6962) {
                note = "The Merkle tree hashing of manifests and containers, with leaves and nodes hashed apart."
            }
            rfc(7468) {
                note = "The textual encoding of PEM: strict reading and writing in krypt-asn1."
            }
            rfc(7748) {
                note = "X25519 and X448: key agreement and the DHKEM of HPKE."
            }
            rfc(7914) {
                note = "scrypt: named as an encryption of private keys krypt refuses."
            }
            rfc(8017) {
                note = "PKCS #1: RSA-PSS and RSA PKCS #1 signatures, RSA-OAEP and the PKCS #1 key formats."
            }
            rfc(8018) {
                note = "PKCS #5: PBKDF2 and PBES2, with iteration bounds from the crypto policy."
            }
            rfc(8032) {
                note = "EdDSA: Ed25519 and Ed448 signatures."
            }
            rfc(8439) {
                note = "ChaCha20-Poly1305: an AEAD of krypt-primitive where the platform has it."
            }
            rfc(9180) {
                note = "HPKE: every mode in common code over the DHKEMs, HKDF and the AEADs, checked against its " +
                    "test vectors."
            }
            rfc(9654) {
                note = "The OCSP nonce: 32 to 128 random bytes in a request, 1 to 128 bytes read, echoed by the " +
                    "responder."
            }
            rfc(9919) {
                note = "The lightweight OCSP profile: SHA-256 identifiers by default and SHA-1 behind an opt-in, " +
                    "GET requests of at most 255 bytes and responders that answer from a cache."
            }
            unicode {
                note = "Untrusted names, subjects and texts are shown through SafeText of Kore."
            }
        }
    }
}
