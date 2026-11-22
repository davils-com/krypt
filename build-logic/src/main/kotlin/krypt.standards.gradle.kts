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
                note = "Time-stamp tokens: a signed manifest of krypt-stream carries them as opaque attachments."
            }
            rfc(3394) {
                note = "AES key wrap: the key wraps of krypt-primitive."
            }
            rfc(4055) {
                note = "RSASSA-PSS and RSAES-OAEP in X.509: the algorithm identifiers and parameters krypt-x509 " +
                    "reads and writes."
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
            rfc(5246) {
                note = "TLS 1.2: offered by krypt-tls only by opt-in and only with forward secret AEAD suites."
            }
            rfc(5280) {
                note = "X.509: the certificates, requests, CRLs and path validation of krypt-x509 and the times of DER."
            }
            rfc(5869) {
                note = "HKDF: implemented over HMAC in common code, so both targets derive alike."
            }
            rfc(5952) {
                note = "The canonical text of IPv6 addresses in the IP address names of krypt-x509."
            }
            rfc(6066) {
                note = "TLS extensions: krypt-tls sends server name indication and chooses identities by it."
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
            rfc(7301) {
                note = "ALPN: the application protocols krypt-tls configures on JSSE."
            }
            rfc(7468) {
                note = "The textual encoding of PEM: strict reading and writing in krypt-asn1."
            }
            rfc(7493) {
                note = "The I-JSON message format: krypt-jose reads and writes JSON without duplicate names, lone " +
                    "surrogates or noncharacters and with integers a double represents exactly."
            }
            rfc(7515) {
                note = "JSON Web Signature: the compact and JSON serializations, detached payloads and the " +
                    "verification of krypt-jose with an algorithm allowlist."
            }
            rfc(7516) {
                note = "JSON Web Encryption: the compact and JSON serializations with several recipients, decrypted " +
                    "with one failure for every wrong key, tag or padding."
            }
            rfc(7517) {
                note = "JSON Web Key and JWK sets: read strictly, written and converted to and from the keys of " +
                    "krypt by krypt-jose."
            }
            rfc(7518) {
                note = "JSON Web Algorithms: the signature, key management and content encryption algorithms of " +
                    "krypt-jose, including the Concat KDF of ECDH-ES and AES-CBC with HMAC."
            }
            rfc(7519) {
                note = "JSON Web Token: the claims, signed, encrypted and nested tokens and their validation by " +
                    "krypt-jose."
            }
            rfc(7520) {
                note = "The JOSE cookbook: the signature and encryption examples krypt-jose checks as known answers."
            }
            rfc(7633) {
                note = "The TLS feature extension of X.509, such as OCSP must-staple, read by krypt-x509 and " +
                    "enforced by krypt-tls."
            }
            rfc(7638) {
                note = "JWK thumbprints, computed by krypt-jose."
            }
            rfc(7748) {
                note = "X25519 and X448: key agreement and the DHKEM of HPKE."
            }
            rfc(7797) {
                note = "Unencoded payloads of a JWS with the b64 header, signed and verified by krypt-jose."
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
            rfc(8037) {
                note = "Octet key pairs in JOSE: Ed25519, Ed448, X25519 and X448 keys, EdDSA signatures and ECDH-ES " +
                    "in krypt-jose."
            }
            rfc(8259) {
                note = "JSON: the bounded and strict parser and writer of krypt-jose."
            }
            rfc(8439) {
                note = "ChaCha20-Poly1305: an AEAD of krypt-primitive where the platform has it."
            }
            rfc(8446) {
                note = "TLS 1.3: the default and only version of krypt-tls unless TLS 1.2 is enabled, over JSSE."
            }
            rfc(8725) {
                note = "The JWT best current practice: allowlists, explicit typing and the claim checks of the token " +
                    "validator of krypt-jose."
            }
            rfc(9180) {
                note = "HPKE: every mode in common code over the DHKEMs, HKDF and the AEADs, checked against its " +
                    "test vectors."
            }
            rfc(9278) {
                note = "JWK thumbprint URIs, computed by krypt-jose."
            }
            rfc(9525) {
                note = "Service identity in TLS: the host name and IP address checks of krypt-x509, applied by " +
                    "krypt-tls."
            }
            rfc(9579) {
                note = "PBMAC1 for PKCS #12: the MAC krypt-keystore writes and one of those it reads."
            }
            rfc(9654) {
                note = "The OCSP nonce: 32 to 128 random bytes in a request, 1 to 128 bytes read, echoed by the " +
                    "responder."
            }
            rfc(9864) {
                note = "Fully specified algorithms for JOSE: the Ed25519 and Ed448 signature algorithms of " +
                    "krypt-jose next to the deprecated EdDSA."
            }
            rfc(9919) {
                note = "The lightweight OCSP profile: SHA-256 identifiers by default and SHA-1 behind an opt-in, " +
                    "GET requests of at most 255 bytes and responders that answer from a cache."
            }
            rfc(10024) {
                note = "The hybrid group X25519MLKEM768 of TLS 1.3, which krypt-tls offers first where the JDK has it."
            }
            unicode {
                note = "Untrusted names, subjects and texts are shown through SafeText of Kore."
            }
        }
    }
}
