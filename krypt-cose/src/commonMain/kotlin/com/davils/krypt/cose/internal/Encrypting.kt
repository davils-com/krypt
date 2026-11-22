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

package com.davils.krypt.cose.internal

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseAlgorithmKind
import com.davils.krypt.cose.CoseEncrypt
import com.davils.krypt.cose.CoseEncrypt0
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.CoseRecipientSpec
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.internal.CoseException.Companion.present
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeyOperation
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

internal class Encrypting(
    private val crypto: Crypto,
    private val permissions: Permissions,
    private val recipients: Recipients,
    private val understood: List<CborItem>,
) {
    suspend fun encrypt0(plaintext: ByteString, key: CoseKey, algorithm: CoseAlgorithm, layer: Layer): CoseEncrypt0 {
        val aead = aeadOf(algorithm)
        val fitting = KeyFit.secretOf(
            key = key,
            algorithm = algorithm,
            operation = CoseKeyOperation.Encrypt,
            bytes = aead.keyBytes,
        )
        val secret = requireNotNull(fitting) { "The key cannot encrypt with ${algorithm.algorithmName}" }
        val buckets = withIv(layer, aead).buckets(algorithm, key.keyId)
        val completed = ivOf(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            baseIv = key.baseIv,
            aead = aead,
        )
        val iv = requireNotNull(completed) { "A Partial IV needs a key with a base IV" }
        val aad = Structures.encryption(
            context = Structures.ENCRYPT0,
            protectedEncoding = buckets.protectedEncoding,
            externalAad = layer.externalAad,
        )
        val ciphertext = crypto.aead.encrypt(
            key = secret,
            nonce = iv,
            plaintext = plaintext,
            associatedData = aad,
            algorithm = aead,
        )
        return CoseEncrypt0(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            ciphertext = ciphertext.takeUnless { layer.isDetached },
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    suspend fun encrypt(
        plaintext: ByteString,
        algorithm: CoseAlgorithm,
        specs: List<CoseRecipientSpec>,
        layer: Layer,
    ): CoseEncrypt {
        val aead = aeadOf(algorithm)
        val buckets = withIv(layer, aead).buckets(algorithm, null)
        val full = ivOf(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            baseIv = null,
            aead = aead,
        )
        val iv = requireNotNull(full) { "The content of a COSE_Encrypt has a full IV" }
        val created = recipients.create(specs, algorithm)
        val key = created.contentKey.use { bytes -> SecretKey.of(bytes) }
        val aad = Structures.encryption(
            context = Structures.ENCRYPT,
            protectedEncoding = buckets.protectedEncoding,
            externalAad = layer.externalAad,
        )
        val ciphertext = crypto.aead.encrypt(
            key = key,
            nonce = iv,
            plaintext = plaintext,
            associatedData = aad,
            algorithm = aead,
        )
        key.destroy()
        return CoseEncrypt(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            ciphertext = ciphertext.takeUnless { layer.isDetached },
            recipients = created.recipients,
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    suspend fun decrypt(message: CoseEncrypt0, request: Request): ByteString {
        val algorithm = algorithmOf(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            request = request,
        )
        val aead = aeadOf(algorithm)
        val ciphertext = Payloads.of(attached = message.ciphertext, detached = request.detached)
        checkIv(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            aead = aead,
        )
        val aad = Structures.encryption(
            context = Structures.ENCRYPT0,
            protectedEncoding = message.protectedEncoding,
            externalAad = request.externalAad,
        )
        val keyId = Layers.keyIdOf(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
        )
        val fitting = request.keys.filter { key -> KeyFit.isKeyIdFit(key, keyId) }
        val sealed = Sealed(ciphertext = ciphertext, aad = aad, aead = aead)
        val plaintext = fitting.firstNotNullOfOrNull { key ->
            openedWith(key = key, message = message, algorithm = algorithm, sealed = sealed)
        }
        return present(plaintext, CoseFailure.DecryptionFailed)
    }

    suspend fun decrypt(message: CoseEncrypt, request: Request): ByteString {
        val algorithm = algorithmOf(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            request = request,
        )
        val aead = aeadOf(algorithm)
        val ciphertext = Payloads.of(attached = message.ciphertext, detached = request.detached)
        checkIv(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            aead = aead,
        )
        val candidates = recipients.candidates(
            recipients = message.recipients,
            keys = request.keys,
            allowed = request.algorithms,
            content = algorithm,
            operation = CoseKeyOperation.Decrypt,
        )
        ensure(candidates.isPermitted, CoseFailure.AlgorithmNotPermitted)
        val iv = ivOf(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            baseIv = null,
            aead = aead,
        )
        val aad = Structures.encryption(
            context = Structures.ENCRYPT,
            protectedEncoding = message.protectedEncoding,
            externalAad = request.externalAad,
        )
        val keys = candidates.keys.map { bytes -> bytes.use { material -> SecretKey.of(material) } }
        val sealed = Sealed(ciphertext = ciphertext, aad = aad, aead = aead)
        val plaintext = iv?.let { nonce ->
            keys.firstNotNullOfOrNull { key -> opened(key = key, iv = nonce, sealed = sealed) }
        }
        keys.forEach { key -> key.destroy() }
        return present(plaintext, CoseFailure.DecryptionFailed)
    }

    private suspend fun algorithmOf(
        protectedHeaders: CoseHeaders,
        unprotectedHeaders: CoseHeaders,
        request: Request,
    ): CoseAlgorithm {
        Layers.checkCritical(protectedHeaders = protectedHeaders, understood = understood)
        val algorithm = Layers.algorithmOf(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            allowed = request.algorithms,
            kind = CoseAlgorithmKind.ContentEncryption,
        )
        permissions.check(algorithm, AlgorithmUse.Verify)
        return algorithm
    }

    private fun withIv(layer: Layer, aead: AeadAlgorithm): Layer {
        val headers = listOf(layer.protectedHeaders, layer.unprotectedHeaders)
        val isGiven = headers.any { bucket -> bucket.iv != null || bucket.partialIv != null }
        if (isGiven) return layer
        val iv = ByteString(crypto.environment.random.bytes(aead.nonceBytes))
        return layer.withUnprotected(layer.unprotectedHeaders.with(HeaderLabels.IV, bytesOf(iv)))
    }

    private fun checkIv(protectedHeaders: CoseHeaders, unprotectedHeaders: CoseHeaders, aead: AeadAlgorithm) {
        val iv = protectedHeaders.iv ?: unprotectedHeaders.iv
        val partial = protectedHeaders.partialIv ?: unprotectedHeaders.partialIv
        val isIvFit = iv?.let { found -> found.size == aead.nonceBytes && partial == null }
        val isPartialFit = partial?.let { found -> found.size <= aead.nonceBytes } == true
        ensure(isIvFit ?: isPartialFit, CoseFailure.Malformed)
    }

    private fun ivOf(
        protectedHeaders: CoseHeaders,
        unprotectedHeaders: CoseHeaders,
        baseIv: ByteString?,
        aead: AeadAlgorithm,
    ): ByteString? {
        val iv = protectedHeaders.iv ?: unprotectedHeaders.iv
        val base = baseIv?.takeIf { bytes -> bytes.size == aead.nonceBytes }
        val partial = base?.takeIf { iv == null }?.let { found ->
            val bytes = (protectedHeaders.partialIv ?: unprotectedHeaders.partialIv).sure()
            Bytes.xor(first = found, second = Bytes.leftPadded(bytes, aead.nonceBytes))
        }
        return iv ?: partial
    }

    private suspend fun openedWith(
        key: CoseKey,
        message: CoseEncrypt0,
        algorithm: CoseAlgorithm,
        sealed: Sealed,
    ): ByteString? {
        val secret = KeyFit.secretOf(
            key = key,
            algorithm = algorithm,
            operation = CoseKeyOperation.Decrypt,
            bytes = sealed.aead.keyBytes,
        ) ?: return null
        val iv = ivOf(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            baseIv = key.baseIv,
            aead = sealed.aead,
        )
        return iv?.let { nonce -> opened(key = secret, iv = nonce, sealed = sealed) }
    }

    private suspend fun opened(key: SecretKey, iv: ByteString, sealed: Sealed): ByteString? = crypto.aead.decrypt(
        key = key,
        nonce = iv,
        ciphertext = sealed.ciphertext,
        associatedData = sealed.aad,
        algorithm = sealed.aead,
    )

    private fun aeadOf(algorithm: CoseAlgorithm): AeadAlgorithm {
        require(algorithm.kind == CoseAlgorithmKind.ContentEncryption) { "${algorithm.algorithmName} encrypts nothing" }
        return algorithm.aead.sure()
    }

    private data class Sealed(val ciphertext: ByteString, val aad: ByteString, val aead: AeadAlgorithm)
}
