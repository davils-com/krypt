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

package com.davils.krypt.primitive.exchange

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm

/**
 * A cipher suite of HPKE: the KEM, the KDF and the AEAD.
 *
 * The ML-KEM suites follow the draft of the IETF for post-quantum HPKE (KEM identifiers 0x0041 and 0x0042) and may
 * change with it.
 *
 * @property kem the KEM.
 * @property kdf the KDF, an HKDF.
 * @property aead the AEAD, or null for a context that only exports secrets.
 * @throws IllegalArgumentException if [kdf] is not an HKDF or [aead] is AES-192-GCM, which HPKE does not name.
 * @since 1.0.0
 */
public class HpkeSuite(public val kem: KemAlgorithm, public val kdf: KdfAlgorithm, public val aead: AeadAlgorithm?) {
    init {
        require(!kdf.isPasswordBased) { "HPKE derives keys with HKDF, not ${kdf.algorithmName}" }
        require(aead != AeadAlgorithm.Aes192Gcm) { "HPKE of RFC 9180 has no identifier for AES-192-GCM" }
    }

    /**
     * Compares the algorithms.
     *
     * @param other the other object.
     * @return true if [other] is the same suite.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is HpkeSuite && kem == other.kem && kdf == other.kdf && aead == other.aead

    /**
     * Hashes the algorithms.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(kem, kdf, aead).hashCode()

    /**
     * Shows the algorithms.
     *
     * @return the suite as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "HpkeSuite(${kem.algorithmName}, ${kdf.algorithmName}, ${aead?.algorithmName ?: "export only"})"

    /**
     * The suites of common choice.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * DHKEM over X25519, HKDF-SHA-256 and AES-256-GCM, the default.
         *
         * @since 1.0.0
         */
        public val X25519Aes256Gcm: HpkeSuite = HpkeSuite(
            KemAlgorithm.DhkemX25519,
            KdfAlgorithm.HkdfSha256,
            AeadAlgorithm.Aes256Gcm,
        )

        /**
         * DHKEM over P-384, HKDF-SHA-384 and AES-256-GCM, for CNSA environments.
         *
         * @since 1.0.0
         */
        public val P384Aes256Gcm: HpkeSuite = HpkeSuite(
            KemAlgorithm.DhkemP384,
            KdfAlgorithm.HkdfSha384,
            AeadAlgorithm.Aes256Gcm,
        )

        /**
         * ML-KEM-768, HKDF-SHA-256 and AES-256-GCM, post-quantum, on the JVM.
         *
         * @since 1.0.0
         */
        public val MlKem768Aes256Gcm: HpkeSuite = HpkeSuite(
            KemAlgorithm.MlKem768,
            KdfAlgorithm.HkdfSha256,
            AeadAlgorithm.Aes256Gcm,
        )
    }
}
