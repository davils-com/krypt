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

import com.davils.krypt.core.Environment
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.RandomSource
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.provider
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.security.spec.NamedParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private const val BYTE_BITS: Int = 8
private const val AES: String = "AES"

@OptIn(LegacyCryptography::class)
internal class JcaBackend(environment: Environment) : Backend {
    private val jca = JcaInstances(environment.provider)
    private val random: SecureRandom = randomOf(environment)

    override val hasIncrementalDigest: Boolean = true

    override suspend fun supports(algorithm: Algorithm): Boolean = jca.probe(algorithm)

    override suspend fun supports(type: KeyType): Boolean = jca.isAvailable {
        jca.keyPairGenerator(JcaNames.keyPairGenerator(type)).initialize(specOf(type))
    }

    override suspend fun digest(algorithm: DigestAlgorithm, data: ByteArray): ByteArray =
        jca.messageDigest(JcaNames.digest(algorithm)).digest(data)

    override fun incrementalDigest(algorithm: DigestAlgorithm): IncrementalDigest {
        val digest = jca.messageDigest(JcaNames.digest(algorithm))
        return object : IncrementalDigest {
            override fun update(bytes: ByteArray, offset: Int, length: Int) {
                digest.update(bytes, offset, length)
            }

            override fun finish(): ByteArray = digest.digest()
        }
    }

    override suspend fun mac(algorithm: MacAlgorithm, key: SecretKey, data: ByteArray): ByteArray {
        val name = JcaNames.mac(algorithm)
        val mac = jca.mac(name)
        key.reveal { bytes -> mac.init(SecretKeySpec(bytes, name)) }
        return mac.doFinal(data)
    }

    override suspend fun seal(
        algorithm: AeadAlgorithm,
        key: SecretKey,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val cipher = aeadCipher(algorithm = algorithm, mode = Cipher.ENCRYPT_MODE, key = key, nonce = nonce)
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    override suspend fun open(
        algorithm: AeadAlgorithm,
        key: SecretKey,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray? {
        val cipher = aeadCipher(algorithm = algorithm, mode = Cipher.DECRYPT_MODE, key = key, nonce = nonce)
        cipher.updateAAD(aad)
        return failing<AEADBadTagException, ByteArray> { cipher.doFinal(ciphertext) }
    }

    override suspend fun aesCbcEncrypt(key: SecretBytes, iv: ByteArray, data: ByteArray): ByteArray =
        cbc(mode = Cipher.ENCRYPT_MODE, key = key, iv = iv).doFinal(data)

    override suspend fun aesCbcDecrypt(key: SecretBytes, iv: ByteArray, data: ByteArray): ByteArray? {
        val cipher = cbc(mode = Cipher.DECRYPT_MODE, key = key, iv = iv)
        return failing<GeneralSecurityException, ByteArray> { cipher.doFinal(data) }
    }

    private fun cbc(mode: Int, key: SecretBytes, iv: ByteArray): Cipher {
        val cipher = jca.cipher("AES/CBC/PKCS5Padding")
        key.reveal { bytes -> cipher.init(mode, SecretKeySpec(bytes, AES), IvParameterSpec(iv), random) }
        return cipher
    }

    override suspend fun wrap(algorithm: KeyWrapAlgorithm, kek: SecretKey, key: ByteArray): ByteArray {
        val cipher = jca.cipher("AES/KW/NoPadding")
        kek.reveal { bytes -> cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(bytes, AES), random) }
        return cipher.doFinal(key)
    }

    override suspend fun unwrap(algorithm: KeyWrapAlgorithm, kek: SecretKey, wrapped: ByteArray): ByteArray? {
        val cipher = jca.cipher("AES/KW/NoPadding")
        kek.reveal { bytes -> cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(bytes, AES), random) }
        return failing<GeneralSecurityException, ByteArray> { cipher.doFinal(wrapped) }
    }

    override suspend fun pbkdf2(
        digest: DigestAlgorithm,
        password: SecretText,
        salt: ByteArray,
        iterations: Int,
        length: Int,
    ): ByteArray {
        val factory = jca.secretKeyFactory("PBKDF2With" + JcaNames.hmacOf(digest))
        return password.reveal { chars ->
            val spec = PBEKeySpec(chars, salt, iterations, length * BYTE_BITS)
            try {
                factory.generateSecret(spec).encoded
            } finally {
                spec.clearPassword()
            }
        }
    }

    override suspend fun generate(type: KeyType): KeyPair {
        val generator = jca.keyPairGenerator(JcaNames.keyPairGenerator(type))
        generator.initialize(specOf(type), random)
        val pair = generator.generateKeyPair()
        return JcaKeys.pairOf(publicKey = pair.public, privateKey = pair.private)
    }

    override suspend fun sign(algorithm: SignatureAlgorithm, key: PrivateKey, data: ByteArray): ByteArray {
        val signature = jca.signature(algorithm)
        signature.initSign(jca.privateKey(key), random)
        signature.update(data)
        return signature.sign()
    }

    override suspend fun verify(
        algorithm: SignatureAlgorithm,
        key: PublicKey,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val verifier = jca.signature(algorithm)
        verifier.initVerify(jca.publicKey(key))
        verifier.update(data)
        return failing<GeneralSecurityException, Boolean> { verifier.verify(signature) } == true
    }

    override suspend fun agree(
        algorithm: KeyAgreementAlgorithm,
        privateKey: PrivateKey,
        publicKey: PublicKey,
    ): ByteArray {
        val agreement = jca.keyAgreement(JcaNames.agreement(algorithm))
        agreement.init(jca.privateKey(privateKey), random)
        agreement.doPhase(jca.publicKey(publicKey), true)
        return agreement.generateSecret()
    }

    override suspend fun encapsulate(algorithm: KemAlgorithm, publicKey: PublicKey): Pair<ByteArray, ByteArray> {
        val encapsulator = jca.kem().newEncapsulator(jca.publicKey(publicKey), random)
        val encapsulated = encapsulator.encapsulate()
        return encapsulated.key().encoded to encapsulated.encapsulation()
    }

    override suspend fun decapsulate(
        algorithm: KemAlgorithm,
        privateKey: PrivateKey,
        encapsulated: ByteArray,
    ): ByteArray? {
        val decapsulator = jca.kem().newDecapsulator(jca.privateKey(privateKey))
        val isSized = encapsulated.size == decapsulator.encapsulationSize()
        val key = encapsulated.takeIf { isSized }?.let { bytes -> decapsulator.decapsulate(bytes) }
        return key?.encoded
    }

    override suspend fun encrypt(
        algorithm: AsymmetricEncryptionAlgorithm,
        publicKey: PublicKey,
        data: ByteArray,
    ): ByteArray {
        val cipher = jca.rsaCipher(algorithm)
        cipher.init(Cipher.ENCRYPT_MODE, jca.publicKey(publicKey), JcaNames.oaep(algorithm), random)
        return cipher.doFinal(data)
    }

    override suspend fun decrypt(
        algorithm: AsymmetricEncryptionAlgorithm,
        privateKey: PrivateKey,
        data: ByteArray,
    ): ByteArray? {
        val cipher = jca.rsaCipher(algorithm)
        cipher.init(Cipher.DECRYPT_MODE, jca.privateKey(privateKey), JcaNames.oaep(algorithm), random)
        return failing<GeneralSecurityException, ByteArray> { cipher.doFinal(data) }
    }

    private fun aeadCipher(algorithm: AeadAlgorithm, mode: Int, key: SecretKey, nonce: ByteArray): Cipher {
        val cipher = jca.cipher(JcaNames.aead(algorithm))
        key.reveal { bytes ->
            cipher.init(
                mode,
                SecretKeySpec(bytes, JcaNames.aeadKey(algorithm)),
                JcaNames.aeadSpec(algorithm, nonce),
            )
        }
        return cipher
    }

    private fun specOf(type: KeyType): AlgorithmParameterSpec {
        val curve = type.curve?.let { found -> ECGenParameterSpec(JcaNames.curve(found)) }
        val rsa = RSAKeyGenParameterSpec(type.bits, RSAKeyGenParameterSpec.F4).takeIf { type.family == KeyFamily.Rsa }
        return curve ?: rsa ?: NamedParameterSpec(JcaNames.generator(type))
    }

    private fun randomOf(environment: Environment): SecureRandom {
        val isPlatform = environment.random === RandomSource.Secure
        return SecureRandom().takeIf { isPlatform } ?: RandomSourceAdapter(environment.random)
    }

    private inline fun <reified E : Exception, R> failing(block: () -> R): R? = try {
        block()
    } catch (_: E) {
        null
    }
}
