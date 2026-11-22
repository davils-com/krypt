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

import com.davils.kore.core.failure.rethrowIfFatal
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.UnsupportedAlgorithmException
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.Provider
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KEM
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import java.security.PrivateKey as JcaPrivateKey
import java.security.PublicKey as JcaPublicKey

@OptIn(LegacyCryptography::class)
internal class JcaInstances(private val provider: Provider?) {
    fun messageDigest(name: String): MessageDigest = instance(
        name,
        { found -> MessageDigest.getInstance(found) },
    ) { found, chosen -> MessageDigest.getInstance(found, chosen) }

    fun mac(name: String): Mac = instance(
        name,
        { found -> Mac.getInstance(found) },
    ) { found, chosen -> Mac.getInstance(found, chosen) }

    fun cipher(name: String): Cipher =
        instance(name, { found -> Cipher.getInstance(found) }) { found, chosen -> Cipher.getInstance(found, chosen) }

    fun rsaCipher(algorithm: AsymmetricEncryptionAlgorithm): Cipher = cipher(JcaNames.rsaCipher(algorithm))

    fun secretKeyFactory(name: String): SecretKeyFactory = instance(
        name,
        { found -> SecretKeyFactory.getInstance(found) },
    ) { found, chosen -> SecretKeyFactory.getInstance(found, chosen) }

    fun keyPairGenerator(name: String): KeyPairGenerator = instance(
        name,
        { found -> KeyPairGenerator.getInstance(found) },
    ) { found, chosen -> KeyPairGenerator.getInstance(found, chosen) }

    fun keyFactory(name: String): KeyFactory = instance(
        name,
        { found -> KeyFactory.getInstance(found) },
    ) { found, chosen -> KeyFactory.getInstance(found, chosen) }

    fun keyAgreement(name: String): KeyAgreement = instance(
        name,
        { found -> KeyAgreement.getInstance(found) },
    ) { found, chosen -> KeyAgreement.getInstance(found, chosen) }

    fun kem(): KEM = instance(
        ML_KEM,
        { found -> KEM.getInstance(found) },
    ) { found, chosen -> KEM.getInstance(found, chosen) }

    fun signature(algorithm: SignatureAlgorithm): Signature {
        val name = JcaNames.signature(algorithm)
        val signature = instance(
            name,
            { found -> Signature.getInstance(found) },
        ) { found, chosen -> Signature.getInstance(found, chosen) }
        JcaNames.pss(algorithm)?.let { spec -> signature.setParameter(spec) }
        return signature
    }

    fun publicKey(key: PublicKey): JcaPublicKey {
        val cached = key.handle as? JcaPublicKey
        val decoded = cached ?: keyFactory(
            JcaNames.keyFactory(key.family),
        ).generatePublic(X509EncodedKeySpec(key.encoded.toByteArray()))
        key.handle = decoded
        return decoded
    }

    fun privateKey(key: PrivateKey): JcaPrivateKey {
        key.checkAlive()
        val cached = key.handle as? JcaPrivateKey
        val decoded = cached ?: decodePrivate(key)
        key.handle = decoded
        return decoded
    }

    private inline fun <T> instance(name: String, byDefault: (String) -> T, byProvider: (String, Provider) -> T): T {
        val chosen = provider ?: return available(name) { byDefault(name) }
        return available(name) { byProvider(name, chosen) }
    }

    private inline fun <T> available(name: String, block: () -> T): T = try {
        block()
    } catch (unavailable: NoSuchAlgorithmException) {
        throw UnsupportedAlgorithmException(name, unavailable)
    }

    fun isAvailable(block: () -> Any): Boolean = try {
        block()
        true
    } catch (unavailable: GeneralSecurityException) {
        unavailable.rethrowIfFatal()
        false
    } catch (unavailable: UnsupportedAlgorithmException) {
        unavailable.rethrowIfFatal()
        false
    }

    fun probe(algorithm: Algorithm): Boolean = isAvailable {
        when (algorithm) {
            is DigestAlgorithm -> messageDigest(JcaNames.digest(algorithm))
            is MacAlgorithm -> mac(JcaNames.mac(algorithm))
            is AeadAlgorithm -> cipher(JcaNames.aead(algorithm))
            is KeyWrapAlgorithm -> cipher(KEY_WRAP)
            is KdfAlgorithm -> kdfProbe(algorithm)
            is SignatureAlgorithm -> signature(algorithm)
            is KeyAgreementAlgorithm -> keyAgreement(JcaNames.agreement(algorithm))
            is AsymmetricEncryptionAlgorithm -> rsaCipher(algorithm)
            is KemAlgorithm -> kemProbe(algorithm)
        }
    }

    private fun kdfProbe(algorithm: KdfAlgorithm): Any = when (algorithm.isPasswordBased) {
        true -> secretKeyFactory("PBKDF2With" + JcaNames.hmacOf(algorithm.digest))
        false -> mac(JcaNames.hmacOf(algorithm.digest))
    }

    private fun kemProbe(algorithm: KemAlgorithm): Any = when (algorithm) {
        KemAlgorithm.MlKem768 -> kem()
        KemAlgorithm.MlKem1024 -> kem()
        KemAlgorithm.DhkemX25519 -> keyAgreement(JcaNames.agreement(KeyAgreementAlgorithm.X25519))
        KemAlgorithm.DhkemP256 -> keyAgreement(JcaNames.agreement(KeyAgreementAlgorithm.EcdhP256))
        KemAlgorithm.DhkemP384 -> keyAgreement(JcaNames.agreement(KeyAgreementAlgorithm.EcdhP384))
        KemAlgorithm.DhkemP521 -> keyAgreement(JcaNames.agreement(KeyAgreementAlgorithm.EcdhP521))
    }

    private fun decodePrivate(key: PrivateKey): JcaPrivateKey {
        val encoding: SecretBytes = checkNotNull(
            key.encodingOrNull(),
        ) { "The private key has neither an encoding nor a handle" }
        val factory = keyFactory(JcaNames.keyFactory(key.family))
        return encoding.reveal { bytes ->
            val spec = PKCS8EncodedKeySpec(bytes)
            factory.generatePrivate(spec)
        }
    }

    private companion object {
        const val ML_KEM: String = "ML-KEM"
        const val KEY_WRAP: String = "AES/KW/NoPadding"
    }
}
