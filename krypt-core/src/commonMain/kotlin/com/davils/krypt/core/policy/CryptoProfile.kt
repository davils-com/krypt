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

package com.davils.krypt.core.policy

/**
 * The starting point of a [CryptoPolicy].
 *
 * @since 1.0.0
 */
public enum class CryptoProfile {
    /**
     * Current best practice and the default: every algorithm that is not legacy, RSA keys of at least 3072 bits for
     * anything new and 2048 bits for verification, RSA-PSS rather than PKCS #1 v1.5 for new signatures, and at least
     * 600,000 PBKDF2 iterations for a new password derivation.
     *
     * @since 1.0.0
     */
    Modern,

    /**
     * [Modern] widened for interoperation with older peers: new RSA keys of 2048 bits and new RSA PKCS #1 v1.5
     * signatures.
     *
     * @since 1.0.0
     */
    Compatible,

    /**
     * The Commercial National Security Algorithm Suite 2.0 of the NSA, with the CNSA 1.0 algorithms it permits during
     * the transition, and nothing else.
     *
     * For something new it permits exactly: AES-256 in GCM and as key wrap; SHA-384 and SHA-512, HMAC, HKDF and
     * PBKDF2 over them (PBKDF2 only with SHA-512, the one of the two krypt offers); ML-KEM-1024 and ML-DSA-87; and, on
     * P-384 only, ECDH, the DHKEM of HPKE and ECDSA with SHA-384. For verification it accepts these and, as CNSA 1.0
     * does, RSA-PSS and RSA PKCS #1 v1.5 signatures with SHA-384 or SHA-512 under RSA keys of at least 3072 bits; RSA
     * is never permitted for anything new. SHA-256, SHA-3, AES-128, ChaCha20-Poly1305, X25519, X448, Ed25519, Ed448,
     * every other curve, ML-KEM-768, ML-DSA-44, ML-DSA-65 and RSA-OAEP are refused for every use.
     *
     * @since 1.0.0
     */
    Cnsa2,

    /**
     * The algorithms FIPS 140-3 approves, and nothing else. The policy also demands a FIPS validated provider on the
     * JVM; krypt cannot prove the validation of a provider and relies on the one the caller configures.
     *
     * @since 1.0.0
     */
    Fips,
}
