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

package com.davils.krypt.cms.internal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.enveloped.ContentEncryption
import com.davils.krypt.cms.enveloped.Credential
import com.davils.krypt.cms.enveloped.EncryptedData
import com.davils.krypt.cms.enveloped.EnvelopedData
import com.davils.krypt.cms.enveloped.Recipient
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.cipher.BlockCiphers
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val TAG_BYTES: Int = 16
private const val VERSION_PASSWORD_OR_OTHER: Int = 3
private const val VERSION_EXTENDED: Int = 2

private val AEADS: Map<ContentEncryption, AeadAlgorithm> = mapOf(
    ContentEncryption.Aes128Gcm to AeadAlgorithm.Aes128Gcm,
    ContentEncryption.Aes256Gcm to AeadAlgorithm.Aes256Gcm,
)

internal class EnvelopedEngine(private val crypto: Crypto, private val limits: CmsLimits) {
    private val codec = EnvelopedCodec(limits)
    private val protection = KeyProtection(crypto)
    private val recovery = KeyRecovery(crypto)

    fun decode(encoded: ByteString): EnvelopedData? = codec.decode(encoded)

    fun decodeEncrypted(encoded: ByteString): EncryptedData? = codec.decodeEncrypted(encoded)

    fun decodeOwn(encoded: ByteString): EnvelopedData = codec.decodeOwn(encoded)

    fun decodeOwnEncrypted(encoded: ByteString): EncryptedData = codec.decodeOwnEncrypted(encoded)

    suspend fun envelop(
        content: ByteString,
        recipients: List<Recipient>,
        encryption: ContentEncryption,
        contentType: ObjectIdentifier,
    ): ByteString {
        require(
            content.size <= limits.maximumContentBytes,
        ) { "The content exceeds ${limits.maximumContentBytes} bytes" }
        require(recipients.size in 1..limits.maximumRecipients) {
            "Enveloped data has 1 to ${limits.maximumRecipients} recipients"
        }
        val random = crypto.environment.random
        val iv = ByteString(random.bytes(Algorithms.ivBytes(encryption)))
        val algorithm = ContentAlgorithm(encryption, iv)
        val isTyped = encryption.isAuthenticated && contentType != ContentTypes.Data
        val authenticated = listOf(
            Attribute(CmsOids.CONTENT_TYPE, listOf(Der.encode { objectIdentifier(contentType) })),
        ).takeIf { isTyped }
        return SecretBytes.random(encryption.keyBytes, random).use { key ->
            val infos = recipients.map { recipient -> protection.protect(recipient, key) }
            val sealed = encrypt(key = key, algorithm = algorithm, content = content, authenticated = authenticated)
            val envelope = EnvelopedCodec.Envelope(
                version = versionOf(recipients, encryption),
                recipients = infos,
                contentType = contentType,
                algorithm = algorithm,
                ciphertext = sealed.first,
                authenticated = authenticated,
                mac = sealed.second,
            )
            codec.encodeEnveloped(envelope)
        }
    }

    suspend fun encrypt(content: ByteString, key: SecretKey, encryption: ContentEncryption): ByteString {
        require(!encryption.isAuthenticated) { "EncryptedData is encrypted with AES-CBC" }
        require(
            key.bits == encryption.keyBytes * Byte.SIZE_BITS,
        ) { "$encryption needs a key of ${encryption.keyBytes} bytes" }
        require(
            content.size <= limits.maximumContentBytes,
        ) { "The content exceeds ${limits.maximumContentBytes} bytes" }
        val iv = ByteString(crypto.environment.random.bytes(Algorithms.ivBytes(encryption)))
        val algorithm = ContentAlgorithm(encryption, iv)
        val ciphertext = key.export().use { bytes ->
            BlockCiphers.aesCbcEncrypt(crypto = crypto, key = bytes, iv = iv, plaintext = content)
        }
        return codec.encodeEncrypted(ContentTypes.Data, algorithm, ciphertext)
    }

    suspend fun decrypt(data: EnvelopedData, credential: Credential): Outcome<ByteString, CmsFailure> {
        val algorithm = data.parts.algorithm ?: return Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
        return decryptWith(data = data, algorithm = algorithm, credential = credential)
    }

    suspend fun decrypt(data: EncryptedData, key: SecretKey): Outcome<ByteString, CmsFailure> {
        val algorithm = data.algorithm ?: return Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
        return decryptWith(data = data, algorithm = algorithm, key = key)
    }

    private suspend fun decryptWith(
        data: EncryptedData,
        algorithm: ContentAlgorithm,
        key: SecretKey,
    ): Outcome<ByteString, CmsFailure> {
        val ciphertext = data.encryptedContent ?: return Outcome.Failure(CmsFailure.ContentMissing)
        return guarded {
            val isKey = key.bits == algorithm.encryption.keyBytes * Byte.SIZE_BITS
            val exported = key.takeIf { isKey }?.export()
            val plain = exported?.use { bytes ->
                BlockCiphers.aesCbcDecrypt(crypto = crypto, key = bytes, iv = algorithm.iv, ciphertext = ciphertext)
            }
            plain?.let { found -> Outcome.Success(found) } ?: Outcome.Failure(CmsFailure.DecryptionFailed)
        }
    }

    private suspend fun decryptWith(
        data: EnvelopedData,
        algorithm: ContentAlgorithm,
        credential: Credential,
    ): Outcome<ByteString, CmsFailure> {
        val ciphertext = data.encryptedContent ?: return Outcome.Failure(CmsFailure.ContentMissing)
        val candidates = data.recipients.mapNotNull { recipient -> recovery.candidate(recipient.parsed, credential) }
        val usable = candidates.filterIsInstance<Candidate.Usable>()
        val failure = CmsFailure.RecipientNotFound.takeIf { candidates.isEmpty() }
            ?: CmsFailure.AlgorithmNotPermitted.takeIf { usable.isEmpty() }
        val opening = Opening(data = data, algorithm = algorithm, ciphertext = ciphertext)
        return failure?.let { found -> Outcome.Failure(found) } ?: guarded { opened(opening, usable) }
    }

    private suspend fun opened(opening: Opening, candidates: List<Candidate.Usable>): Outcome<ByteString, CmsFailure> {
        val algorithm = opening.algorithm
        val keyBytes = algorithm.encryption.keyBytes
        val recovered = candidates.firstNotNullOfOrNull { candidate ->
            recoverQuietly(candidate)?.takeIf { key -> key.size == keyBytes }
        }
        val isRecovered = recovered != null
        val key = recovered ?: SecretBytes.random(keyBytes, crypto.environment.random)
        val plain = key.use { bytes ->
            decryptContent(
                key = bytes,
                algorithm = algorithm,
                ciphertext = opening.ciphertext,
                data = opening.data,
            )
        }
        return plain?.takeIf { isRecovered }.mapOr(
            absent = { Outcome.Failure(CmsFailure.DecryptionFailed) },
            present = { found -> Outcome.Success(found) },
        )
    }

    private suspend fun recoverQuietly(candidate: Candidate.Usable): SecretBytes? = try {
        recovery.recover(candidate)
    } catch (refused: PolicyViolationException) {
        throw RefusedException(refused)
    } catch (ignored: CryptoException) {
        null
    }

    private suspend fun decryptContent(
        key: SecretBytes,
        algorithm: ContentAlgorithm,
        ciphertext: ByteString,
        data: EnvelopedData,
    ): ByteString? = when (algorithm.encryption.isAuthenticated) {
        true -> {
            val aead = AEADS.getValue(algorithm.encryption)
            val mac = data.parts.mac
            val associated = data.parts.authenticated.mapOr(absent = { ByteString() }, present = { set -> set.asSet })
            val secretKey = SecretKey.of(key)
            val plain = crypto.aead.decrypt(
                key = secretKey,
                nonce = algorithm.iv,
                ciphertext = concat(listOf(ciphertext, mac)),
                associatedData = associated,
                algorithm = aead,
            )
            secretKey.destroy()
            plain
        }

        false -> {
            BlockCiphers.aesCbcDecrypt(crypto = crypto, key = key, iv = algorithm.iv, ciphertext = ciphertext)
        }
    }

    private suspend fun encrypt(
        key: SecretBytes,
        algorithm: ContentAlgorithm,
        content: ByteString,
        authenticated: List<Attribute>?,
    ): Pair<ByteString, ByteString?> = when (algorithm.encryption.isAuthenticated) {
        true -> {
            val secretKey = SecretKey.of(key)
            val sealed = crypto.aead.encrypt(
                key = secretKey,
                nonce = algorithm.iv,
                plaintext = content,
                associatedData = authenticated.mapOr(
                    absent = { ByteString() },
                    present = { attributes -> AttributeCodec.encodeSet(attributes) },
                ),
                algorithm = AEADS.getValue(algorithm.encryption),
            )
            secretKey.destroy()
            val split = sealed.size - TAG_BYTES
            sealed.substring(
                startIndex = 0,
                endIndex = split,
            ) to sealed.substring(startIndex = split, endIndex = sealed.size)
        }

        false -> {
            BlockCiphers.aesCbcEncrypt(crypto = crypto, key = key, iv = algorithm.iv, plaintext = content) to null
        }
    }

    private suspend fun guarded(block: suspend () -> Outcome<ByteString, CmsFailure>): Outcome<ByteString, CmsFailure> =
        try {
            block()
        } catch (ignored: RefusedException) {
            Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
        } catch (ignored: PolicyViolationException) {
            Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
        } catch (ignored: CryptoException) {
            Outcome.Failure(CmsFailure.DecryptionFailed)
        }

    private fun versionOf(recipients: List<Recipient>, encryption: ContentEncryption): Int {
        val isThree = recipients.any { recipient -> KeyProtection.isVersionThree(recipient) }
        val isTwo = recipients.any { recipient -> !KeyProtection.isVersionZero(recipient) }
        val version = VERSION_PASSWORD_OR_OTHER.takeIf { isThree } ?: VERSION_EXTENDED.takeIf { isTwo } ?: 0
        return version.takeUnless { encryption.isAuthenticated } ?: 0
    }

    private data class Opening(val data: EnvelopedData, val algorithm: ContentAlgorithm, val ciphertext: ByteString)

    private class RefusedException(cause: PolicyViolationException) : RuntimeException(cause)
}
