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

package com.davils.krypt.tls

import com.davils.krypt.core.algorithm.AeadAlgorithm

/**
 * A cipher suite krypt allows: an AEAD with forward secret key exchange, in the order of preference.
 *
 * A suite is offered only if the crypto policy of the environment permits its AEAD for protection and, for a suite of
 * TLS 1.2, only if TLS 1.2 is enabled.
 *
 * @property suiteName the name of the suite in JSSE and in the IANA registry.
 * @property aead the AEAD that protects the records.
 * @property version the version the suite belongs to.
 * @since 1.0.0
 */
public enum class CipherSuite(
    public val suiteName: String,
    public val aead: AeadAlgorithm,
    public val version: TlsVersion,
) {
    /**
     * TLS_AES_256_GCM_SHA384 of TLS 1.3.
     *
     * @since 1.0.0
     */
    Aes256GcmSha384("TLS_AES_256_GCM_SHA384", AeadAlgorithm.Aes256Gcm, TlsVersion.Tls13),

    /**
     * TLS_AES_128_GCM_SHA256 of TLS 1.3.
     *
     * @since 1.0.0
     */
    Aes128GcmSha256("TLS_AES_128_GCM_SHA256", AeadAlgorithm.Aes128Gcm, TlsVersion.Tls13),

    /**
     * TLS_CHACHA20_POLY1305_SHA256 of TLS 1.3.
     *
     * @since 1.0.0
     */
    ChaCha20Poly1305Sha256("TLS_CHACHA20_POLY1305_SHA256", AeadAlgorithm.ChaCha20Poly1305, TlsVersion.Tls13),

    /**
     * TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 of TLS 1.2.
     *
     * @since 1.0.0
     */
    EcdheEcdsaAes256GcmSha384("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", AeadAlgorithm.Aes256Gcm, TlsVersion.Tls12),

    /**
     * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 of TLS 1.2.
     *
     * @since 1.0.0
     */
    EcdheEcdsaAes128GcmSha256("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", AeadAlgorithm.Aes128Gcm, TlsVersion.Tls12),

    /**
     * TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 of TLS 1.2.
     *
     * @since 1.0.0
     */
    EcdheEcdsaChaCha20Poly1305Sha256(
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        AeadAlgorithm.ChaCha20Poly1305,
        TlsVersion.Tls12,
    ),

    /**
     * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 of TLS 1.2.
     *
     * @since 1.0.0
     */
    EcdheRsaAes256GcmSha384("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", AeadAlgorithm.Aes256Gcm, TlsVersion.Tls12),

    /**
     * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 of TLS 1.2.
     *
     * @since 1.0.0
     */
    EcdheRsaAes128GcmSha256("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", AeadAlgorithm.Aes128Gcm, TlsVersion.Tls12),

    /**
     * TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 of TLS 1.2.
     *
     * @since 1.0.0
     */
    EcdheRsaChaCha20Poly1305Sha256(
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        AeadAlgorithm.ChaCha20Poly1305,
        TlsVersion.Tls12,
    ),
}
