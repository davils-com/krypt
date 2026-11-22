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

package com.davils.krypt.primitive.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.core.ConstantTime
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.key.KeyFailure
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val X25519_BASE: Int = 9
private const val X448_BASE: Int = 5
private const val X25519_BYTES: Int = 32
private const val X448_BYTES: Int = 56
private const val ML_KEM_1024_BITS: Int = 1_024

internal object KeyConsistency {
    private val PROBE: ByteString = "krypt key consistency probe".encodeToByteString()

    suspend fun checked(crypto: Crypto, key: PrivateKey): Outcome<PrivateKey, KeyFailure> = when (key.family) {
        KeyFamily.Rsa -> Outcome.Success(key)
        KeyFamily.X25519 -> derived(crypto = crypto, key = key, algorithm = KeyAgreementAlgorithm.X25519)
        KeyFamily.X448 -> derived(crypto = crypto, key = key, algorithm = KeyAgreementAlgorithm.X448)
        KeyFamily.Ed25519 -> signing(crypto = crypto, key = key)
        KeyFamily.Ed448 -> signing(crypto = crypto, key = key)
        KeyFamily.Ec -> signing(crypto = crypto, key = key)
        KeyFamily.MlDsa -> signing(crypto = crypto, key = key)
        KeyFamily.MlKem -> encapsulating(crypto = crypto, key = key)
    }

    private suspend fun derived(
        crypto: Crypto,
        key: PrivateKey,
        algorithm: KeyAgreementAlgorithm,
    ): Outcome<PrivateKey, KeyFailure> {
        if (!crypto.capabilities.supports(algorithm)) return unchecked(key)
        val raw = crypto.backend.agree(algorithm = algorithm, privateKey = key, publicKey = basePoint(algorithm))
        val derived = raw?.let { bytes -> publicKeyOf(algorithm = algorithm, raw = bytes) }
        val claim = key.publicKey
        val isConsistent = derived != null && (claim == null || claim == derived)
        return verdict(key = key, isConsistent = isConsistent, publicKey = derived)
    }

    private suspend fun signing(crypto: Crypto, key: PrivateKey): Outcome<PrivateKey, KeyFailure> {
        val claim = key.publicKey ?: return Outcome.Success(key)
        val algorithm = crypto.signatures.defaultFor(family = key.family, curve = key.curve, bits = key.bits)
        val isConsistent = probed(crypto = crypto, algorithm = algorithm) {
            val signature = crypto.backend.sign(algorithm = algorithm, key = key, data = PROBE.toByteArray())
            crypto.backend.verify(
                algorithm = algorithm,
                key = claim,
                data = PROBE.toByteArray(),
                signature = signature,
            )
        }
        return outcomeOf(key = key, isConsistent = isConsistent, claim = claim)
    }

    private suspend fun encapsulating(crypto: Crypto, key: PrivateKey): Outcome<PrivateKey, KeyFailure> {
        val claim = key.publicKey ?: return Outcome.Success(key)
        val algorithm = KemAlgorithm.MlKem1024.takeIf { key.bits == ML_KEM_1024_BITS } ?: KemAlgorithm.MlKem768
        val isConsistent = probed(crypto = crypto, algorithm = algorithm) {
            val (secret, encapsulated) = crypto.backend.encapsulate(algorithm = algorithm, publicKey = claim)
            val opened = crypto.backend.decapsulate(
                algorithm = algorithm,
                privateKey = key,
                encapsulated = encapsulated,
            ) ?: ByteArray(0)
            val isEqual = ConstantTime.equals(first = secret, second = opened)
            secret.fill(0)
            opened.fill(0)
            isEqual
        }
        return outcomeOf(key = key, isConsistent = isConsistent, claim = claim)
    }

    private suspend inline fun probed(crypto: Crypto, algorithm: Algorithm, probe: () -> Boolean): Boolean? {
        if (!crypto.capabilities.supports(algorithm)) return null
        return try {
            probe()
        } catch (ignored: CryptoException) {
            false
        }
    }

    private fun outcomeOf(key: PrivateKey, isConsistent: Boolean?, claim: PublicKey): Outcome<PrivateKey, KeyFailure> =
        when (isConsistent) {
            null -> unchecked(key)
            true -> Outcome.Success(key)
            false -> verdict(key = key, isConsistent = false, publicKey = claim)
        }

    private fun verdict(
        key: PrivateKey,
        isConsistent: Boolean,
        publicKey: PublicKey?,
    ): Outcome<PrivateKey, KeyFailure> {
        if (!isConsistent) return Outcome.Failure(KeyFailure.Malformed)
        return Outcome.Success(replaced(key = key, publicKey = publicKey))
    }

    private fun unchecked(key: PrivateKey): Outcome<PrivateKey, KeyFailure> =
        Outcome.Success(replaced(key = key, publicKey = null))

    private fun replaced(key: PrivateKey, publicKey: PublicKey?): PrivateKey {
        val replaced = key.withPublic(publicKey)
        key.destroy()
        return replaced
    }

    private fun basePoint(algorithm: KeyAgreementAlgorithm): PublicKey {
        val isX448 = algorithm == KeyAgreementAlgorithm.X448
        val size = X448_BYTES.takeIf { isX448 } ?: X25519_BYTES
        val base = X448_BASE.takeIf { isX448 } ?: X25519_BASE
        val point = ByteArray(size).also { bytes -> bytes[0] = base.toByte() }
        return checkNotNull(publicKeyOf(algorithm = algorithm, raw = point))
    }

    private fun publicKeyOf(algorithm: KeyAgreementAlgorithm, raw: ByteArray): PublicKey? {
        val oid = Oids.X448.takeIf { algorithm == KeyAgreementAlgorithm.X448 } ?: Oids.X25519
        val identifier = Der.encode { sequence { objectIdentifier(oid) } }
        val spki = KeyCodec.spkiOf(algorithm = identifier, publicBits = BitString(ByteString(raw)))
        return KeyCodec.publicKeyOf(spki).getOrNull()
    }
}
