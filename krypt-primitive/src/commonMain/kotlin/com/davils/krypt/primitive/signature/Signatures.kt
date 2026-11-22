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

package com.davils.krypt.primitive.signature

import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.internal.EcdsaSignatures
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

private const val ML_DSA_44: Int = 44
private const val ML_DSA_65: Int = 65

/**
 * Digital signatures: EdDSA, ECDSA, RSA-PSS, RSA PKCS #1 v1.5 and, on the JVM, ML-DSA.
 *
 * The algorithm must belong to the family of the key; ECDSA uses the curve of the key. [defaultFor] picks the
 * algorithm that fits a key best: the matching hash for ECDSA, RSA-PSS with SHA-256 for RSA.
 *
 * @since 1.0.0
 */
public class Signatures internal constructor(private val crypto: Crypto) {
    /**
     * Signs [data] with [key].
     *
     * @param key the private key.
     * @param data the message.
     * @param algorithm the scheme; [defaultFor] the key by default.
     * @param format how an ECDSA signature is encoded; [SignatureFormat.Der] by default.
     * @return the signature.
     * @throws IllegalArgumentException if [algorithm] does not fit the key.
     * @throws IllegalStateException if the key was destroyed.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the algorithm or the key.
     * @since 1.0.0
     */
    public suspend fun sign(
        key: PrivateKey,
        data: ByteString,
        algorithm: SignatureAlgorithm = defaultFor(key.family, key.curve, key.bits),
        format: SignatureFormat = SignatureFormat.Der,
    ): ByteString {
        require(algorithm.family == key.family) { "${algorithm.algorithmName} does not sign with a ${key.family} key" }
        crypto.permit(algorithm, AlgorithmUse.Protect)
        crypto.permitKey(key, AlgorithmUse.Protect)
        val signature = crypto.backend.sign(algorithm, key, data.toByteArray())
        val isDer = algorithm.family == KeyFamily.Ec && format == SignatureFormat.Der
        return ByteString(signature.takeUnless { isDer } ?: EcdsaSignatures.derOf(signature))
    }

    /**
     * Verifies [signature] over [data] with [key].
     *
     * @param key the public key.
     * @param data the message.
     * @param signature the signature.
     * @param algorithm the scheme; [defaultFor] the key by default.
     * @param format how an ECDSA signature is encoded; [SignatureFormat.Der] by default.
     * @return whether the signature is valid; a malformed signature is invalid.
     * @throws IllegalArgumentException if [algorithm] does not fit the key.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids the algorithm or the key.
     * @since 1.0.0
     */
    public suspend fun verify(
        key: PublicKey,
        data: ByteString,
        signature: ByteString,
        algorithm: SignatureAlgorithm = defaultFor(key.family, key.curve, key.bits),
        format: SignatureFormat = SignatureFormat.Der,
    ): Verification {
        require(
            algorithm.family == key.family,
        ) { "${algorithm.algorithmName} does not verify with a ${key.family} key" }
        crypto.permit(algorithm, AlgorithmUse.Verify)
        crypto.permitKey(key, AlgorithmUse.Verify)
        val isDer = algorithm.family == KeyFamily.Ec && format == SignatureFormat.Der
        val fieldBytes = key.curve?.fieldBytes ?: 0
        val bytes = signature.toByteArray()
        val raw = bytes.takeUnless { isDer } ?: EcdsaSignatures.rawOf(der = bytes, fieldBytes = fieldBytes)
        val isValid = raw?.let { candidate ->
            crypto.backend.verify(
                algorithm = algorithm,
                key = key,
                data = data.toByteArray(),
                signature = candidate,
            )
        } == true
        return Verification.of(isValid)
    }

    /**
     * Returns a [Signer] over [key], for the components that sign through the signer interface.
     *
     * @param key the private key, whose public key must be known.
     * @param algorithm the scheme; [defaultFor] the key by default.
     * @return the signer.
     * @throws IllegalArgumentException if the public key of [key] is unknown or [algorithm] does not fit.
     * @since 1.0.0
     */
    public fun signer(
        key: PrivateKey,
        algorithm: SignatureAlgorithm = defaultFor(
            key.family,
            key.curve,
            key.bits,
        ),
    ): Signer {
        val publicKey = requireNotNull(key.publicKey) { "A signer needs the public key of its private key" }
        require(algorithm.family == key.family) { "${algorithm.algorithmName} does not sign with a ${key.family} key" }
        val signatures = this
        return object : Signer {
            override val algorithm: SignatureAlgorithm = algorithm
            override val publicKey: PublicKey = publicKey

            override suspend fun sign(data: ByteString): ByteString = signatures.sign(
                key = key,
                data = data,
                algorithm = algorithm,
            )

            override fun toString(): String = "Signer(${algorithm.algorithmName}, $publicKey)"
        }
    }

    /**
     * Picks the signature algorithm that fits a key best.
     *
     * @param family the family of the key.
     * @param curve the curve of an elliptic curve key.
     * @param bits the size of the key, which picks the parameter set of ML-DSA.
     * @return the algorithm.
     * @throws IllegalArgumentException if keys of [family] do not sign, as X25519 or ML-KEM keys.
     * @since 1.0.0
     */
    public fun defaultFor(family: KeyFamily, curve: EllipticCurve?, bits: Int): SignatureAlgorithm = when (family) {
        KeyFamily.Ed25519 -> SignatureAlgorithm.Ed25519
        KeyFamily.Ed448 -> SignatureAlgorithm.Ed448
        KeyFamily.Ec -> ecdsaFor(curve)
        KeyFamily.Rsa -> SignatureAlgorithm.RsaPssSha256
        KeyFamily.MlDsa -> mlDsaFor(bits)
        KeyFamily.X25519 -> throw IllegalArgumentException("An X25519 key does not sign")
        KeyFamily.X448 -> throw IllegalArgumentException("An X448 key does not sign")
        KeyFamily.MlKem -> throw IllegalArgumentException("An ML-KEM key does not sign")
    }

    private fun ecdsaFor(curve: EllipticCurve?): SignatureAlgorithm = when (curve) {
        EllipticCurve.P256 -> SignatureAlgorithm.EcdsaSha256
        EllipticCurve.P384 -> SignatureAlgorithm.EcdsaSha384
        EllipticCurve.P521 -> SignatureAlgorithm.EcdsaSha512
        null -> SignatureAlgorithm.EcdsaSha256
    }

    private fun mlDsaFor(bits: Int): SignatureAlgorithm = ML_DSA[bits] ?: SignatureAlgorithm.MlDsa87

    private companion object {
        val ML_DSA: Map<Int, SignatureAlgorithm> = mapOf(
            ML_DSA_44 to SignatureAlgorithm.MlDsa44,
            ML_DSA_65 to SignatureAlgorithm.MlDsa65,
        )
    }
}
