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

@file:OptIn(ExperimentalWasmJsInterop::class)

package com.davils.krypt.primitive.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.UnsupportedAlgorithmException
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val BYTE_BITS: Int = 8
private const val WRAP_OVERHEAD: Int = 8
private const val ENCRYPT_DECRYPT: String = "encrypt,decrypt"
private const val WRAP_UNWRAP: String = "wrapKey,unwrapKey"
private const val RAW: String = "raw"

internal class WebCryptoBackend : Backend {
    override val hasIncrementalDigest: Boolean = false

    override suspend fun supports(algorithm: Algorithm): Boolean = WebCryptoProbes.supports(algorithm)

    override suspend fun supports(type: KeyType): Boolean = WebCryptoProbes.supports(type)

    override suspend fun digest(algorithm: DigestAlgorithm, data: ByteArray): ByteArray {
        val name = WebCryptoNames.digest(algorithm) ?: throw UnsupportedAlgorithmException(algorithm.algorithmName)
        return JsBytes.withJs(data) { input -> JsBytes.fromJs(required(algorithm) { digest(name, input).settled() }) }
    }

    override fun incrementalDigest(algorithm: DigestAlgorithm): IncrementalDigest? = null

    override suspend fun mac(algorithm: MacAlgorithm, key: SecretKey, data: ByteArray): ByteArray {
        val hash = checkNotNull(WebCryptoNames.digest(algorithm.digest))
        val cryptoKey = WebCryptoKeys.secret(
            key,
            KeyImport(name = "HMAC:$hash", algorithm = withHash(HMAC, hash), usages = "sign"),
        )
        return JsBytes.withJs(data) { input -> JsBytes.fromJs(sign(named(HMAC), cryptoKey, input).settled()) }
    }

    override suspend fun seal(
        algorithm: AeadAlgorithm,
        key: SecretKey,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val name = WebCryptoParameters.aead(algorithm)
        val cryptoKey = WebCryptoKeys.secret(
            key,
            KeyImport(name = name, algorithm = named(name), usages = ENCRYPT_DECRYPT),
        )
        val parameters = aeadParameters(name, JsBytes.toJs(nonce), JsBytes.toJs(aad))
        return JsBytes.withJs(plaintext) { input -> JsBytes.fromJs(encrypt(parameters, cryptoKey, input).settled()) }
    }

    override suspend fun open(
        algorithm: AeadAlgorithm,
        key: SecretKey,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray? {
        val name = WebCryptoParameters.aead(algorithm)
        val cryptoKey = WebCryptoKeys.secret(
            key,
            KeyImport(name = name, algorithm = named(name), usages = ENCRYPT_DECRYPT),
        )
        val parameters = aeadParameters(name, JsBytes.toJs(nonce), JsBytes.toJs(aad))
        val opened = JsBytes.withJs(ciphertext) { input -> attempt { decrypt(parameters, cryptoKey, input).settled() } }
        return opened?.let { buffer -> JsBytes.fromJs(buffer) }
    }

    override suspend fun aesCbcEncrypt(key: SecretBytes, iv: ByteArray, data: ByteArray): ByteArray {
        val cryptoKey = cbcKey(key)
        val parameters = withIv(WebCryptoNames.AES_CBC, JsBytes.toJs(iv))
        return JsBytes.withJs(data) { input -> JsBytes.fromJs(encrypt(parameters, cryptoKey, input).settled()) }
    }

    override suspend fun aesCbcDecrypt(key: SecretBytes, iv: ByteArray, data: ByteArray): ByteArray? {
        val cryptoKey = cbcKey(key)
        val parameters = withIv(WebCryptoNames.AES_CBC, JsBytes.toJs(iv))
        val result = JsBytes.withJs(data) { input -> attempt { decrypt(parameters, cryptoKey, input).settled() } }
        return result?.let { buffer -> JsBytes.fromJs(buffer) }
    }

    private suspend fun cbcKey(key: SecretBytes): JsAny {
        val algorithm = named(WebCryptoNames.AES_CBC)
        return key.reveal { bytes ->
            JsBytes.withJs(
                bytes,
            ) { raw -> importKey(f = RAW, d = raw, a = algorithm, e = false, u = usages(ENCRYPT_DECRYPT)).settled() }
        }
    }

    override suspend fun wrap(algorithm: KeyWrapAlgorithm, kek: SecretKey, key: ByteArray): ByteArray {
        val wrapping = WebCryptoKeys.secret(
            kek,
            KeyImport(name = WebCryptoNames.AES_KW, algorithm = named(WebCryptoNames.AES_KW), usages = WRAP_UNWRAP),
        )
        val target = hmacImport(WebCryptoNames.SHA_256, key.size * BYTE_BITS)
        val toWrap = JsBytes.withJs(
            key,
        ) { raw -> importKey(f = RAW, d = raw, a = target, e = true, u = usages("sign")).settled() }
        return JsBytes.fromJs(wrapKey(toWrap, wrapping).settled())
    }

    override suspend fun unwrap(algorithm: KeyWrapAlgorithm, kek: SecretKey, wrapped: ByteArray): ByteArray? {
        val wrapping = WebCryptoKeys.secret(
            kek,
            KeyImport(name = WebCryptoNames.AES_KW, algorithm = named(WebCryptoNames.AES_KW), usages = WRAP_UNWRAP),
        )
        val target = hmacImport(WebCryptoNames.SHA_256, (wrapped.size - WRAP_OVERHEAD) * BYTE_BITS)
        val unwrapped = JsBytes.withJs(
            wrapped,
        ) { input -> attempt { unwrapKey(w = input, k = wrapping, t = target).settled() } }
        return unwrapped?.let { key -> JsBytes.fromJs(exportKey(RAW, key).settled()) }
    }

    override suspend fun pbkdf2(
        digest: DigestAlgorithm,
        password: SecretText,
        salt: ByteArray,
        iterations: Int,
        length: Int,
    ): ByteArray {
        val hash = checkNotNull(WebCryptoNames.digest(digest))
        val algorithm = named("PBKDF2")
        val baseKey = password.utf8().use { secret ->
            secret.reveal { bytes ->
                JsBytes.withJs(
                    bytes,
                ) { raw ->
                    importKey(
                        f = RAW,
                        d = raw,
                        a = algorithm,
                        e = false,
                        u = usages(WebCryptoNames.DERIVE),
                    ).settled()
                }
            }
        }
        val parameters = pbkdf2Parameters(JsBytes.toJs(salt), iterations, hash)
        return JsBytes.fromJs(deriveBits(parameters, baseKey, length * BYTE_BITS).settled())
    }

    override suspend fun generate(type: KeyType): KeyPair {
        val (name, keyUsages) = WebCryptoNames.generation(type.family) ?: throw UnsupportedAlgorithmException(type.name)
        val pair = required(
            type,
        ) { generateKey(WebCryptoParameters.generation(type, name), usages(keyUsages)).settled() }
        val spki = JsBytes.fromJs(exportKey("spki", publicOf(pair)).settled())
        val pkcs8 = JsBytes.fromJs(exportKey("pkcs8", privateOf(pair)).settled())
        val publicKey = checkNotNull(KeyCodec.publicKeyOf(ByteString(spki)).getOrNull())
        val parsed = SecretBytes.adopt(pkcs8).use { secret -> checkNotNull(KeyCodec.privateKeyOf(secret).getOrNull()) }
        val privateKey = parsed.withPublic(publicKey)
        parsed.destroy()
        return KeyPair(publicKey = publicKey, privateKey = privateKey)
    }

    override suspend fun sign(algorithm: SignatureAlgorithm, key: PrivateKey, data: ByteArray): ByteArray {
        val import = KeyImport(
            name = "sign:${algorithm.name}",
            algorithm = WebCryptoParameters.signatureImport(algorithm, key.curve),
            usages = "sign",
        )
        key.checkAlive()
        val signed = attempt {
            val cryptoKey = WebCryptoKeys.private(key, import)
            JsBytes.withJs(data) { input -> sign(WebCryptoParameters.signature(algorithm), cryptoKey, input).settled() }
        }
        return JsBytes.fromJs(signed ?: throw platformRefusal())
    }

    override suspend fun verify(
        algorithm: SignatureAlgorithm,
        key: PublicKey,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val import = KeyImport(
            name = "verify:${algorithm.name}",
            algorithm = WebCryptoParameters.signatureImport(algorithm, key.curve),
            usages = "verify",
        )
        val parameters = WebCryptoParameters.signature(algorithm)
        val result = attempt {
            val cryptoKey = WebCryptoKeys.public(key, import)
            JsBytes.withJs(data) { input -> verify(parameters, cryptoKey, JsBytes.toJs(signature), input).settled() }
        }
        return result?.toBoolean() == true
    }

    override suspend fun agree(
        algorithm: KeyAgreementAlgorithm,
        privateKey: PrivateKey,
        publicKey: PublicKey,
    ): ByteArray? {
        val (name, importAlgorithm) = WebCryptoParameters.agreement(algorithm)
        privateKey.checkAlive()
        val ownImport = KeyImport(
            name = "agree:${algorithm.name}",
            algorithm = importAlgorithm,
            usages = WebCryptoNames.DERIVE,
        )
        val peerImport = KeyImport(name = "agree:${algorithm.name}", algorithm = importAlgorithm, usages = "")
        val derived = attempt {
            val own = WebCryptoKeys.private(privateKey, ownImport)
            val peer = WebCryptoKeys.public(publicKey, peerImport)
            deriveBits(agreementParameters(name, peer), own, algorithm.secretBytes * BYTE_BITS).settled()
        }
        return derived?.let { bits -> JsBytes.fromJs(bits) }
    }

    override suspend fun encapsulate(algorithm: KemAlgorithm, publicKey: PublicKey): Pair<ByteArray, ByteArray> =
        throw UnsupportedAlgorithmException(algorithm.algorithmName)

    override suspend fun decapsulate(
        algorithm: KemAlgorithm,
        privateKey: PrivateKey,
        encapsulated: ByteArray,
    ): ByteArray? = throw UnsupportedAlgorithmException(algorithm.algorithmName)

    override suspend fun encrypt(
        algorithm: AsymmetricEncryptionAlgorithm,
        publicKey: PublicKey,
        data: ByteArray,
    ): ByteArray {
        val import = oaepImport(algorithm, usage = "encrypt")
        val encrypted = attempt {
            val cryptoKey = WebCryptoKeys.public(publicKey, import)
            JsBytes.withJs(data) { input -> encrypt(named(WebCryptoNames.RSA_OAEP), cryptoKey, input).settled() }
        }
        return JsBytes.fromJs(encrypted ?: throw platformRefusal())
    }

    override suspend fun decrypt(
        algorithm: AsymmetricEncryptionAlgorithm,
        privateKey: PrivateKey,
        data: ByteArray,
    ): ByteArray? {
        val import = oaepImport(algorithm, usage = "decrypt")
        privateKey.checkAlive()
        val result = attempt {
            val cryptoKey = WebCryptoKeys.private(privateKey, import)
            JsBytes.withJs(data) { input -> decrypt(named(WebCryptoNames.RSA_OAEP), cryptoKey, input).settled() }
        }
        return result?.let { buffer -> JsBytes.fromJs(buffer) }
    }

    private fun oaepImport(algorithm: AsymmetricEncryptionAlgorithm, usage: String): KeyImport {
        val digest = algorithm.digest ?: throw UnsupportedAlgorithmException(algorithm.algorithmName)
        val hash = checkNotNull(WebCryptoNames.digest(digest))
        return KeyImport(name = "oaep:$hash", algorithm = withHash(WebCryptoNames.RSA_OAEP, hash), usages = usage)
    }

    private inline fun <R> required(what: Any, block: () -> R): R = try {
        block()
    } catch (unavailable: WebCryptoRejection) {
        throw UnsupportedAlgorithmException(what.toString(), unavailable)
    }

    private inline fun <R> attempt(block: () -> R): R? = try {
        block()
    } catch (_: WebCryptoRejection) {
        null
    }

    private companion object {
        const val HMAC: String = "HMAC"
    }
}
