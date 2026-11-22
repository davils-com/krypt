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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.cose.key

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.internal.KeyFit
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

/**
 * A key of COSE by RFC 9052 section 7: a key of krypt with the type, the curve, the key id, the algorithm and the
 * operations of a COSE_Key.
 *
 * An asymmetric key holds a [publicKey], a [privateKey] or both; a symmetric key holds a [secretKey]. When
 * [algorithm] is set, the key serves that algorithm only; when [operations] is not empty, it serves those operations
 * only. The private and secret parts never appear in [toString]. A key is immutable; destroying its private or secret
 * key destroys it for every holder.
 *
 * @property type the key type.
 * @property curve the curve of an EC2 or OKP key, or null for an RSA or symmetric key.
 * @property keyId the key id, or null.
 * @property algorithm the only algorithm the key serves, or null for every algorithm that fits it.
 * @property operations the only operations the key serves, or empty for every operation that fits it.
 * @property baseIv the base IV of a symmetric key, which a Partial IV completes, or null.
 * @property publicKey the public key, or null.
 * @property privateKey the private key, or null.
 * @property secretKey the symmetric key, or null.
 * @since 1.0.0
 */
public class CoseKey internal constructor(
    public val type: CoseKeyType,
    public val curve: CoseCurve?,
    public val keyId: ByteString?,
    public val algorithm: CoseAlgorithm?,
    public val operations: Set<CoseKeyOperation>,
    public val baseIv: ByteString?,
    public val publicKey: PublicKey?,
    public val privateKey: PrivateKey?,
    public val secretKey: SecretKey?,
) {
    private val shown: List<Any?> get() = listOf(type, curve, keyId, algorithm, operations, baseIv, publicKey)

    init {
        val isAlgorithmFit = algorithm == null || KeyFit.isTypeFit(this, algorithm)
        require(isAlgorithmFit) { "The algorithm of a COSE key fits its type and curve" }
    }

    /**
     * Compares every part; private keys compare by identity and symmetric keys in constant time.
     *
     * @param other the other object.
     * @return true if [other] is the same key.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CoseKey &&
        shown == other.shown &&
        privateKey == other.privateKey &&
        secretKey == other.secretKey

    /**
     * Hashes the public parts.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = shown.hashCode()

    /**
     * Shows the public parts and whether the key holds private or secret material, never that material.
     *
     * @return the key as text.
     * @since 1.0.0
     */
    override fun toString(): String {
        val ids = listOfNotNull(keyId).joinToString { bytes -> Hex.encode(bytes) }
        val id = ids.ifEmpty { NONE }
        val secret = SafeText.REDACTED.takeIf { privateKey != null || secretKey != null } ?: NONE
        val names = listOfNotNull(algorithm).joinToString { found -> found.algorithmName }
        val name = names.ifEmpty { NONE }
        return "CoseKey(type=$type, curve=${curve ?: NONE}, keyId=$id, algorithm=$name, " +
            "operations=$operations, private=$secret)"
    }

    /**
     * The factories of a COSE key.
     *
     * @since 1.0.0
     */
    public companion object {
        private const val NONE: String = "none"

        /**
         * Returns the COSE key of [publicKey], to verify, to encrypt to by ECDH or to describe.
         *
         * @param publicKey the public key: P-256, P-384, P-521, Ed25519, Ed448, X25519, X448 or RSA.
         * @param keyId the key id, or null.
         * @param algorithm the only algorithm the key serves, or null.
         * @param operations the only operations the key serves, or empty.
         * @return the key.
         * @throws IllegalArgumentException if COSE has no key type for the key or [algorithm] does not fit it.
         * @since 1.0.0
         */
        public fun of(
            publicKey: PublicKey,
            keyId: ByteString? = null,
            algorithm: CoseAlgorithm? = null,
            operations: Set<CoseKeyOperation> = emptySet(),
        ): CoseKey {
            val curve = curveOf(publicKey.family, publicKey.curve)
            return CoseKey(
                type = typeOf(curve),
                curve = curve,
                keyId = keyId,
                algorithm = algorithm,
                operations = operations.toSet(),
                baseIv = null,
                publicKey = publicKey,
                privateKey = null,
                secretKey = null,
            )
        }

        /**
         * Returns the COSE key of [privateKey], to sign or to decrypt by ECDH.
         *
         * @param privateKey the private key: P-256, P-384, P-521, Ed25519, Ed448, X25519, X448 or RSA.
         * @param publicKey its public key, the one the private key knows by default.
         * @param keyId the key id, or null.
         * @param algorithm the only algorithm the key serves, or null.
         * @param operations the only operations the key serves, or empty.
         * @return the key.
         * @throws IllegalArgumentException if COSE has no key type for the key, the public key is of another kind or
         *   [algorithm] does not fit the key.
         * @since 1.0.0
         */
        public fun of(
            privateKey: PrivateKey,
            publicKey: PublicKey? = privateKey.publicKey,
            keyId: ByteString? = null,
            algorithm: CoseAlgorithm? = null,
            operations: Set<CoseKeyOperation> = emptySet(),
        ): CoseKey {
            val isSameKind = publicKey == null ||
                (publicKey.family == privateKey.family && publicKey.curve == privateKey.curve)
            require(isSameKind) { "The public key of a COSE key is of the kind of its private key" }
            val curve = curveOf(privateKey.family, privateKey.curve)
            return CoseKey(
                type = typeOf(curve),
                curve = curve,
                keyId = keyId,
                algorithm = algorithm,
                operations = operations.toSet(),
                baseIv = null,
                publicKey = publicKey,
                privateKey = privateKey,
                secretKey = null,
            )
        }

        /**
         * Returns the COSE key of the symmetric [secretKey], to MAC, to encrypt directly or to wrap content keys.
         *
         * @param secretKey the symmetric key.
         * @param keyId the key id, or null.
         * @param algorithm the only algorithm the key serves, or null.
         * @param operations the only operations the key serves, or empty.
         * @param baseIv the base IV a Partial IV completes, or null.
         * @return the key.
         * @throws IllegalArgumentException if [algorithm] does not fit a symmetric key.
         * @since 1.0.0
         */
        public fun of(
            secretKey: SecretKey,
            keyId: ByteString? = null,
            algorithm: CoseAlgorithm? = null,
            operations: Set<CoseKeyOperation> = emptySet(),
            baseIv: ByteString? = null,
        ): CoseKey = CoseKey(
            type = CoseKeyType.Symmetric,
            curve = null,
            keyId = keyId,
            algorithm = algorithm,
            operations = operations.toSet(),
            baseIv = baseIv,
            publicKey = null,
            privateKey = null,
            secretKey = secretKey,
        )

        private fun curveOf(family: KeyFamily, curve: EllipticCurve?): CoseCurve? {
            val found = CoseCurve.entries.firstOrNull { candidate ->
                candidate.family == family && candidate.curve == curve
            }
            require(found != null || family == KeyFamily.Rsa) { "COSE has no key type for a key of $family" }
            return found
        }

        private fun typeOf(curve: CoseCurve?): CoseKeyType = listOfNotNull(curve?.keyType, CoseKeyType.Rsa).first()
    }
}
