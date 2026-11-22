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

package com.davils.krypt.primitive

import com.davils.krypt.core.Environment
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.cipher.Aeads
import com.davils.krypt.primitive.cipher.AsymmetricEncryptions
import com.davils.krypt.primitive.cipher.KeyWraps
import com.davils.krypt.primitive.exchange.Hpke
import com.davils.krypt.primitive.exchange.Kems
import com.davils.krypt.primitive.exchange.KeyAgreements
import com.davils.krypt.primitive.hash.Digests
import com.davils.krypt.primitive.hash.KeyDerivations
import com.davils.krypt.primitive.hash.Macs
import com.davils.krypt.primitive.internal.Backend
import com.davils.krypt.primitive.internal.KeyShape
import com.davils.krypt.primitive.internal.platformBackend
import com.davils.krypt.primitive.key.Keys
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.password.PasswordHasher
import com.davils.krypt.primitive.signature.Signatures

/**
 * The cryptographic primitives of krypt, bound to one [Environment]: its randomness, its policy and, on the JVM, its
 * provider.
 *
 * Every operation is suspending, because WebCrypto answers asynchronously; on the JVM it runs on the caller's thread,
 * so heavy work such as an RSA key generation or a password derivation belongs on `Dispatchers.Default`. Every
 * operation asks the policy first and throws [PolicyViolationException] when it forbids the algorithm, and throws
 * [UnsupportedAlgorithmException] when the platform lacks it. A failure that depends on the data, such as a wrong tag,
 * is never an exception.
 *
 * A crypto object holds no secrets and is thread safe; create one per environment and share it.
 *
 * @property environment the environment.
 * @since 1.0.0
 */
public class Crypto(public val environment: Environment = Environment.Default) {
    internal val backend: Backend = platformBackend(environment)

    /**
     * What the platform can do.
     *
     * @since 1.0.0
     */
    public val capabilities: Capabilities = Capabilities(backend)

    /**
     * Generating, reading and writing keys.
     *
     * @since 1.0.0
     */
    public val keys: Keys = Keys(this)

    /**
     * Message digests.
     *
     * @since 1.0.0
     */
    public val digests: Digests = Digests(this)

    /**
     * Message authentication codes.
     *
     * @since 1.0.0
     */
    public val macs: Macs = Macs(this)

    /**
     * Key derivation: HKDF and PBKDF2.
     *
     * @since 1.0.0
     */
    public val derivations: KeyDerivations = KeyDerivations(this)

    /**
     * Authenticated encryption.
     *
     * @since 1.0.0
     */
    public val aead: Aeads = Aeads(this)

    /**
     * Key wrapping.
     *
     * @since 1.0.0
     */
    public val keyWraps: KeyWraps = KeyWraps(this)

    /**
     * Encryption with RSA public keys.
     *
     * @since 1.0.0
     */
    public val encryptions: AsymmetricEncryptions = AsymmetricEncryptions(this)

    /**
     * Digital signatures.
     *
     * @since 1.0.0
     */
    public val signatures: Signatures = Signatures(this)

    /**
     * Key agreement.
     *
     * @since 1.0.0
     */
    public val agreements: KeyAgreements = KeyAgreements(this)

    /**
     * Key encapsulation.
     *
     * @since 1.0.0
     */
    public val kems: Kems = Kems(this)

    /**
     * Hybrid public key encryption of RFC 9180.
     *
     * @since 1.0.0
     */
    public val hpke: Hpke = Hpke(this)

    /**
     * Password hashing for storing user passwords.
     *
     * @since 1.0.0
     */
    public val passwords: PasswordHasher = PasswordHasher(this)

    internal fun permit(algorithm: Algorithm, use: AlgorithmUse) {
        if (!environment.policy.permits(
                algorithm,
                use,
            )
        ) {
            throw PolicyViolationException("${algorithm.algorithmName} ($use)")
        }
    }

    internal fun permitKey(key: PublicKey, use: AlgorithmUse) {
        permitShape(KeyShape(family = key.family, bits = key.bits, curve = key.curve), use)
    }

    internal fun permitKey(key: PrivateKey, use: AlgorithmUse) {
        permitShape(KeyShape(family = key.family, bits = key.bits, curve = key.curve), use)
    }

    internal fun permitKey(type: KeyType, use: AlgorithmUse) {
        permitShape(KeyShape(family = type.family, bits = type.bits, curve = type.curve), use)
    }

    internal fun isPermitted(shape: KeyShape, use: AlgorithmUse): Boolean {
        val policy = environment.policy
        val isRsaPermitted = shape.family != KeyFamily.Rsa || policy.permitsRsa(shape.bits, use)
        val curve = shape.curve
        val isCurvePermitted = curve == null || policy.permitsCurve(curve)
        return isRsaPermitted && isCurvePermitted
    }

    private fun permitShape(shape: KeyShape, use: AlgorithmUse) {
        val isPermitted = isPermitted(shape, use)
        if (!isPermitted) throw PolicyViolationException("a ${shape.family} key of ${shape.bits} bits ($use)")
    }

    /**
     * Shows the environment.
     *
     * @return the crypto object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Crypto($environment)"
}
