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

package com.davils.krypt.cms.enveloped

import com.davils.krypt.cms.internal.Algorithms
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

/**
 * A recipient of enveloped data: who can recover the content-encryption key, and how it is protected for them.
 *
 * @since 1.0.0
 */
public sealed interface Recipient {
    /**
     * Key transport with RSA-OAEP by RFC 3560 to the RSA key of [certificate], a KeyTransRecipientInfo.
     *
     * @property certificate the recipient's certificate with an RSA key.
     * @property algorithm RSA-OAEP with SHA-256, SHA-384 or SHA-512 and MGF1 of the same digest.
     * @property isKeyIdentifierUsed true to name the certificate by its subject key identifier.
     * @constructor Describes the recipient.
     * @throws IllegalArgumentException if [algorithm] is not RSA-OAEP.
     * @since 1.0.0
     */
    public class KeyTransport(
        public val certificate: Certificate,
        public val algorithm: AsymmetricEncryptionAlgorithm = AsymmetricEncryptionAlgorithm.RsaOaepSha256,
        public val isKeyIdentifierUsed: Boolean = false,
    ) : Recipient {
        internal val digest: DigestAlgorithm = requireNotNull(algorithm.digest) {
            "CMS transports keys with RSA-OAEP only, not ${algorithm.algorithmName}"
        }

        private val values: List<Any?> get() = listOf(certificate, algorithm, isKeyIdentifierUsed)

        /**
         * Compares every property.
         *
         * @param other the other object.
         * @return true if [other] describes the same recipient.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is KeyTransport && values == other.values

        /**
         * Hashes every property.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = values.hashCode()

        /**
         * Shows the subject and the algorithm.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String = "KeyTransport(${certificate.subject}, ${algorithm.algorithmName})"
    }

    /**
     * Ephemeral-static key agreement to the key of [certificate], a KeyAgreeRecipientInfo: ECDH on P-256, P-384 or
     * P-521 with the KDF of ANSI X9.63 by RFC 5753, or X25519 and X448 with HKDF by RFC 8418.
     *
     * @property certificate the recipient's certificate with an EC, X25519 or X448 key.
     * @property digest the digest of the key derivation: SHA-256, SHA-384 or SHA-512.
     * @property wrap the AES key wrap of the content-encryption key.
     * @property isKeyIdentifierUsed true to name the certificate by its subject key identifier.
     * @property userKeyingMaterial optional user keying material that enters the key derivation.
     * @constructor Describes the recipient.
     * @since 1.0.0
     */
    public class KeyAgreement(
        public val certificate: Certificate,
        public val digest: DigestAlgorithm = DigestAlgorithm.Sha256,
        public val wrap: KeyWrapAlgorithm = KeyWrapAlgorithm.Aes256Kw,
        public val isKeyIdentifierUsed: Boolean = false,
        public val userKeyingMaterial: ByteString? = null,
    ) : Recipient {
        private val values: List<Any?> get() = listOf(
            certificate,
            digest,
            wrap,
            isKeyIdentifierUsed,
            userKeyingMaterial,
        )

        /**
         * Compares every property.
         *
         * @param other the other object.
         * @return true if [other] describes the same recipient.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is KeyAgreement && values == other.values

        /**
         * Hashes every property.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = values.hashCode()

        /**
         * Shows the subject and the algorithms.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String =
            "KeyAgreement(${certificate.subject}, ${digest.algorithmName}, ${wrap.algorithmName})"
    }

    /**
     * A key-encryption key both sides share, a KEKRecipientInfo with AES key wrap by RFC 3394.
     *
     * @property keyIdentifier the identifier both sides know the key by.
     * @property key the AES key of 16 or 32 bytes.
     * @constructor Describes the recipient.
     * @throws IllegalArgumentException if [key] is neither 16 nor 32 bytes.
     * @since 1.0.0
     */
    public class Kek(public val keyIdentifier: ByteString, public val key: SecretKey) : Recipient {
        internal val wrap: KeyWrapAlgorithm = requireNotNull(Algorithms.wrapOf(key.bits / Byte.SIZE_BITS)) {
            "A key-encryption key has 16 or 32 bytes"
        }

        /**
         * Compares the identifier and the key, the key in constant time.
         *
         * @param other the other object.
         * @return true if [other] describes the same recipient.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Kek &&
            listOf(
                keyIdentifier,
                key,
            ) == listOf(other.keyIdentifier, other.key)

        /**
         * Hashes the identifier only.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = keyIdentifier.hashCode()

        /**
         * Shows the identifier, never the key.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Kek(${Hex.encode(keyIdentifier)})"
    }

    /**
     * A password, a PasswordRecipientInfo of RFC 3211: PBKDF2 derives an AES-256 key that wraps the
     * content-encryption key with the PWRI-KEK wrap over AES-CBC.
     *
     * The crypto policy bounds [iterations] for new derivations; a password is only as strong as its entropy.
     *
     * @property password the password.
     * @property iterations the PBKDF2 iterations.
     * @property prf PBKDF2 with HMAC-SHA-256 or HMAC-SHA-512.
     * @constructor Describes the recipient.
     * @throws IllegalArgumentException if [prf] is not PBKDF2.
     * @since 1.0.0
     */
    public class Password(
        public val password: SecretText,
        public val iterations: Int,
        public val prf: KdfAlgorithm = KdfAlgorithm.Pbkdf2Sha256,
    ) : Recipient {
        init {
            require(prf.isPasswordBased) { "A password recipient derives with PBKDF2, not ${prf.algorithmName}" }
        }

        /**
         * Compares every property, the password in constant time.
         *
         * @param other the other object.
         * @return true if [other] describes the same recipient.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Password &&
            listOf(
                password,
                iterations,
                prf,
            ) == listOf(other.password, other.iterations, other.prf)

        /**
         * Hashes the iterations and the derivation, never the password.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = listOf(iterations, prf).hashCode()

        /**
         * Shows the derivation, never the password.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Password(${prf.algorithmName}, $iterations iterations)"
    }

    /**
     * A key encapsulation to the ML-KEM key of [certificate], a KEMRecipientInfo of RFC 9629 with ML-KEM by RFC 9936,
     * on the JVM only.
     *
     * @property certificate the recipient's certificate with an ML-KEM-768 or ML-KEM-1024 key.
     * @property kdf HKDF with SHA-256, SHA-384 or SHA-512.
     * @property wrap the AES key wrap of the content-encryption key.
     * @property isKeyIdentifierUsed true to name the certificate by its subject key identifier.
     * @property userKeyingMaterial optional user keying material that enters the key derivation.
     * @constructor Describes the recipient.
     * @throws IllegalArgumentException if [kdf] is not HKDF.
     * @since 1.0.0
     */
    public class Kem(
        public val certificate: Certificate,
        public val kdf: KdfAlgorithm = KdfAlgorithm.HkdfSha256,
        public val wrap: KeyWrapAlgorithm = KeyWrapAlgorithm.Aes256Kw,
        public val isKeyIdentifierUsed: Boolean = false,
        public val userKeyingMaterial: ByteString? = null,
    ) : Recipient {
        private val values: List<Any?> get() = listOf(certificate, kdf, wrap, isKeyIdentifierUsed, userKeyingMaterial)

        init {
            require(!kdf.isPasswordBased) { "A KEM recipient derives with HKDF, not ${kdf.algorithmName}" }
        }

        /**
         * Compares every property.
         *
         * @param other the other object.
         * @return true if [other] describes the same recipient.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Kem && values == other.values

        /**
         * Hashes every property.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = values.hashCode()

        /**
         * Shows the subject and the algorithms.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Kem(${certificate.subject}, ${kdf.algorithmName}, ${wrap.algorithmName})"
    }
}
