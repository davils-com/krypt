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

            rfc(822) {
                note = "Internet mail addresses: the syntax of the rfc822Name of X.509, which krypt-x509 checks " +
                    "strictly."
            }
            rfc(1421) {
                note = "PEM with the Proc-Type and DEK-Info headers of OpenSSL: krypt recognises the legacy " +
                    "encryption and refuses it."
            }
            rfc(2104) {
                note = "HMAC: the MACs of krypt-primitive and the base of HKDF, computed by JCA or WebCrypto."
            }
            rfc(2986) {
                note = "PKCS #10: certification requests, built and verified by krypt-x509."
            }
            rfc(3161) {
                note = "Time-stamp tokens: requests, responses, tokens and the authority of krypt-cms, and " +
                    "opaque attachments of the signed manifests of krypt-stream."
            }
            rfc(3211) {
                note = "Password recipients of CMS: PBKDF2 within the policy and the PWRI-KEK wrap over AES-CBC in " +
                    "krypt-cms."
            }
            rfc(3394) {
                note = "AES key wrap: the key wraps of krypt-primitive."
            }
            rfc(3560) {
                note = "RSA-OAEP key transport in CMS: the KeyTransRecipientInfo of krypt-cms with SHA-2 and MGF1."
            }
            rfc(4055) {
                note = "RSASSA-PSS and RSAES-OAEP in X.509: the algorithm identifiers and parameters krypt-x509 " +
                    "reads and writes."
            }
            rfc(4056) {
                note = "RSASSA-PSS in CMS: the signature algorithm of signers in krypt-cms, with the parameters of " +
                    "RFC 4055."
            }
            rfc(4231) {
                note = "The HMAC-SHA-2 test vectors the MAC tests check against."
            }
            rfc(4514) {
                note = "The string form of distinguished names, written with escaping by krypt-x509."
            }
            rfc(4519) {
                note = "The LDAP attribute types the distinguished names of krypt-x509 know by name."
            }
            rfc(4648) {
                note = "Base64 and base64url: strict, constant-time codecs of krypt-core that refuse every " +
                    "non-canonical input."
            }
            rfc(5035) {
                note = "ESS signing-certificate-v2: written by krypt-cms with SHA-256 and checked against the signer " +
                    "certificate."
            }
            rfc(5083) {
                note = "AuthEnvelopedData: authenticated enveloped content of krypt-cms with AES-GCM."
            }
            rfc(5084) {
                note = "AES-GCM in CMS: a nonce of 12 bytes and a tag of 16 bytes, through the AEADs of " +
                    "krypt-primitive."
            }
            rfc(5280) {
                note = "X.509: the certificates, requests, CRLs and path validation of krypt-x509 and the times of DER."
            }
            rfc(5652) {
                note = "CMS: signed, enveloped and encrypted data of krypt-cms in strict DER, with countersignatures."
            }
            rfc(5753) {
                note = "ECDH in CMS: ephemeral-static key agreement with the X9.63 KDF over SHA-2 in common code."
            }
            rfc(5816) {
                note = "ESSCertIDv2 in time-stamp tokens: the signing-certificate-v2 attribute of krypt-cms tokens."
            }
            rfc(5869) {
                note = "HKDF: implemented over HMAC in common code, so both targets derive alike."
            }
            rfc(5952) {
                note = "The canonical text of IPv6 addresses in the IP address names of krypt-x509."
            }
            rfc(6070) {
                note = "The PBKDF2-HMAC-SHA-1 test vectors the legacy derivation of krypt-primitive checks against."
            }
            rfc(6960) {
                note = "OCSP: requests, strict responses, their verification against the issuer or a delegated " +
                    "responder, the revocation checker of path validation and the logic of a responder."
            }
            rfc(6962) {
                note = "Certificate Transparency: the timestamps and log lists of krypt-ct, and the Merkle trees of " +
                    "krypt-stream with leaves and nodes hashed apart."
            }
            rfc(7093) {
                note = "Key identifiers: krypt-x509 derives them from the SHA-256 of the subject public key."
            }
            rfc(7292) {
                note = "PKCS #12: read and written by krypt-keystore with PBES2 and a MAC, the legacy protection " +
                    "refused."
            }
            rfc(7468) {
                note = "The textual encoding of PEM: strict reading and writing in krypt-asn1."
            }
            rfc(7633) {
                note = "The TLS feature extension of X.509, such as OCSP must-staple, read by krypt-x509."
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
            rfc(8418) {
                note = "X25519 and X448 key agreement in CMS with HKDF: recipients of krypt-cms where the platform " +
                    "has them."
            }
            rfc(8419) {
                note = "EdDSA in CMS: Ed25519 with SHA-512 and Ed448 without signed attributes in krypt-cms."
            }
            rfc(8439) {
                note = "ChaCha20-Poly1305: an AEAD of krypt-primitive where the platform has it."
            }
            rfc(9180) {
                note = "HPKE: every mode in common code over the DHKEMs, HKDF and the AEADs, checked against its " +
                    "test vectors."
            }
            rfc(9525) {
                note = "Service identity in TLS: the host name and IP address checks of krypt-x509."
            }
            rfc(9579) {
                note = "PBMAC1 for PKCS #12: the MAC krypt-keystore writes and one of those it reads."
            }
            rfc(9629) {
                note = "KEMRecipientInfo of CMS: KEM recipients of krypt-cms with HKDF and AES key wrap."
            }
            rfc(9654) {
                note = "The OCSP nonce: 32 to 128 random bytes in a request, 1 to 128 bytes read, echoed by the " +
                    "responder."
            }
            rfc(9882) {
                note = "ML-DSA in CMS: pure ML-DSA signers of krypt-cms with SHA-512 for the signed attributes."
            }
            rfc(9919) {
                note = "The lightweight OCSP profile: SHA-256 identifiers by default and SHA-1 behind an opt-in, " +
                    "GET requests of at most 255 bytes and responders that answer from a cache."
            }
            rfc(9936) {
                note = "ML-KEM in CMS: KEM recipients of krypt-cms with ML-KEM-768 and ML-KEM-1024 on the JVM."
            }
            unicode {
                note = "Untrusted names, subjects and texts are shown through SafeText of Kore."
            }
        }
    }
}
