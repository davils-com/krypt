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

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.CoseRecipient
import com.davils.krypt.cose.CoseRecipientSpec
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeyOperation
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

internal class Recipients(
    private val crypto: Crypto,
    private val permissions: Permissions,
    private val keyCodec: KeyCodec,
    private val understood: List<CborItem>,
) {
    suspend fun create(specs: List<CoseRecipientSpec>, content: CoseAlgorithm): Created {
        require(specs.isNotEmpty()) { "A message has at least one recipient" }
        val isDirect = specs.any { spec -> spec.algorithm.keyWrap == null }
        require(!isDirect || specs.size == 1) { "A direct recipient is the only recipient" }
        val size = Permissions.contentKeyBytes(content)
        if (isDirect) return direct(spec = specs.single(), content = content, size = size)
        val contentKey = SecretBytes.random(size, crypto.environment.random)
        return Created(recipients = specs.map { spec -> wrapped(spec, contentKey) }, contentKey = contentKey)
    }

    suspend fun candidates(
        recipients: List<CoseRecipient>,
        keys: List<CoseKey>,
        allowed: Set<CoseAlgorithm>,
        content: CoseAlgorithm,
        operation: CoseKeyOperation,
    ): Candidates {
        val attempts = recipients.mapNotNull { recipient ->
            val algorithm = permissions.distributionOf(
                protectedHeaders = recipient.protectedHeaders,
                unprotectedHeaders = recipient.unprotectedHeaders,
                allowed = allowed,
            )
            algorithm?.let { found ->
                Attempt(recipient = recipient, algorithm = found, content = content, operation = operation)
            }
        }
        val found = attempts.flatMap { attempt -> keysOf(attempt, keys) }
        return Candidates(keys = found, isPermitted = attempts.isNotEmpty())
    }

    private suspend fun direct(spec: CoseRecipientSpec, content: CoseAlgorithm, size: Int): Created {
        if (spec.algorithm.kdf != null) return agreed(spec = spec, algorithmId = content.id, size = size)
        val secret = spec.key.secretKey.sure()
        require(secret.bits == size * Byte.SIZE_BITS) { "The direct key fits ${content.algorithmName}" }
        val recipient = layer(
            spec = spec,
            protectedHeaders = CoseHeaders.Empty,
            unprotected = spec.unprotectedHeaders,
            ciphertext = Bytes.Empty,
        )
        return Created(recipients = listOf(recipient), contentKey = secret.export())
    }

    private suspend fun wrapped(spec: CoseRecipientSpec, contentKey: SecretBytes): CoseRecipient {
        val wrap = spec.algorithm.keyWrap.sure()
        if (spec.algorithm.kdf != null) return agreedWrapped(spec = spec, wrap = wrap, contentKey = contentKey)
        val ciphertext = crypto.keyWraps.wrap(kek = spec.key.secretKey.sure(), key = contentKey, algorithm = wrap)
        return layer(
            spec = spec,
            protectedHeaders = CoseHeaders.Empty,
            unprotected = spec.unprotectedHeaders,
            ciphertext = ciphertext,
        )
    }

    private suspend fun agreedWrapped(
        spec: CoseRecipientSpec,
        wrap: KeyWrapAlgorithm,
        contentKey: SecretBytes,
    ): CoseRecipient {
        val algorithmId = Permissions.kdfAlgorithmId(algorithm = spec.algorithm, content = spec.algorithm)
        val agreed = agreed(spec = spec, algorithmId = algorithmId, size = wrap.keyBytes)
        val kek = agreed.contentKey.use { bytes -> SecretKey.of(bytes) }
        val ciphertext = crypto.keyWraps.wrap(kek = kek, key = contentKey, algorithm = wrap)
        kek.destroy()
        return agreed.recipients.single().withCiphertext(ciphertext)
    }

    private suspend fun agreed(spec: CoseRecipientSpec, algorithmId: Long, size: Int): Created {
        val curve = spec.key.curve.sure()
        val type = KeyType.entries.first { candidate ->
            candidate.family == curve.family && candidate.curve == curve.curve
        }
        val ephemeral = crypto.keys.generate(type)
        val ephemeralKey = keyCodec.encode(CoseKey.of(ephemeral.publicKey), isPrivateIncluded = false)
        val protectedHeaders = Layers.withAlgorithm(
            protectedHeaders = spec.protectedHeaders,
            unprotectedHeaders = spec.unprotectedHeaders,
            algorithm = spec.algorithm,
        )
        val recipient = layer(
            spec = spec,
            protectedHeaders = protectedHeaders,
            unprotected = spec.unprotectedHeaders.with(HeaderLabels.EPHEMERAL_KEY, ephemeralKey),
            ciphertext = Bytes.Empty,
        )
        val derived = derive(
            privateKey = ephemeral.privateKey,
            publicKey = spec.key.publicKey.sure(),
            recipient = recipient,
            algorithm = spec.algorithm,
            algorithmId = algorithmId,
            size = size,
        )
        ephemeral.privateKey.destroy()
        return Created(recipients = listOf(recipient), contentKey = derived)
    }

    private fun layer(
        spec: CoseRecipientSpec,
        protectedHeaders: CoseHeaders,
        unprotected: CoseHeaders,
        ciphertext: ByteString,
    ): CoseRecipient {
        val isProtected = protectedHeaders[HeaderLabels.ALGORITHM] != null
        val withAlgorithm = unprotected.takeIf { isProtected } ?: Layers.withAlgorithm(
            protectedHeaders = unprotected,
            unprotectedHeaders = CoseHeaders.Empty,
            algorithm = spec.algorithm,
        )
        val unprotectedHeaders = Layers.withKeyId(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = withAlgorithm,
            keyId = spec.key.keyId,
        )
        Layers.requireDistinct(protectedHeaders = protectedHeaders, unprotectedHeaders = unprotectedHeaders)
        return CoseRecipient(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            ciphertext = ciphertext,
            recipients = emptyList(),
            protectedEncoding = Layers.encodingOf(protectedHeaders),
        )
    }

    private fun CoseRecipient.withCiphertext(ciphertext: ByteString): CoseRecipient = CoseRecipient(
        protectedHeaders = protectedHeaders,
        unprotectedHeaders = unprotectedHeaders,
        ciphertext = ciphertext,
        recipients = recipients,
        protectedEncoding = protectedEncoding,
    )

    private suspend fun derive(
        privateKey: PrivateKey,
        publicKey: PublicKey,
        recipient: CoseRecipient,
        algorithm: CoseAlgorithm,
        algorithmId: Long,
        size: Int,
    ): SecretBytes {
        val headers = listOf(recipient.protectedHeaders, recipient.unprotectedHeaders)
        val context = Structures.kdfContext(
            algorithmId = algorithmId,
            keyBits = size * Byte.SIZE_BITS,
            protectedEncoding = recipient.protectedEncoding,
            headers = headers,
        )
        val salt = headers.firstNotNullOfOrNull { bucket -> bucket.parameters.bytesAt(HeaderLabels.SALT) }
        return crypto.agreements.agree(privateKey, publicKey).use { shared ->
            crypto.derivations.hkdf(
                inputKey = shared,
                salt = salt ?: Bytes.Empty,
                info = context,
                length = size,
                algorithm = algorithm.kdf.sure(),
            )
        }
    }

    private suspend fun keysOf(attempt: Attempt, keys: List<CoseKey>): List<SecretBytes> {
        val headers = attempt.recipient.protectedHeaders
        val isUnderstood = headers.critical.all { label -> label in understood && headers[label] != null }
        val keyId = Layers.keyIdOf(
            protectedHeaders = headers,
            unprotectedHeaders = attempt.recipient.unprotectedHeaders,
        )
        val fitting = keys.filter { key -> isUnderstood && KeyFit.isKeyIdFit(key, keyId) }
        if (attempt.algorithm.kdf != null) return agreedKeys(attempt, fitting)
        return symmetricKeys(attempt, fitting)
    }

    private suspend fun symmetricKeys(attempt: Attempt, keys: List<CoseKey>): List<SecretBytes> {
        val size = Permissions.contentKeyBytes(attempt.content)
        val isPlain = attempt.recipient.protectedHeaders.isEmpty
        val usable = keys.filter { isPlain }
        val wrap = attempt.algorithm.keyWrap ?: return usable.mapNotNull { key -> directSecret(attempt, key, size) }
        val ciphertext = attempt.recipient.ciphertext ?: Bytes.Empty
        return usable.mapNotNull { key ->
            val kek = KeyFit.secretOf(
                key = key,
                algorithm = attempt.algorithm,
                operation = CoseKeyOperation.UnwrapKey,
                bytes = wrap.keyBytes,
            )
            kek?.let { found -> unwrapped(kek = found, ciphertext = ciphertext, wrap = wrap, size = size) }
        }
    }

    private fun directSecret(attempt: Attempt, key: CoseKey, size: Int): SecretBytes? {
        val operation = attempt.operation
        val direct = KeyFit.secretOf(key = key, algorithm = attempt.algorithm, operation = operation, bytes = size)
        val content = KeyFit.secretOf(key = key, algorithm = attempt.content, operation = operation, bytes = size)
        return (direct ?: content)?.export()
    }

    private suspend fun agreedKeys(attempt: Attempt, keys: List<CoseKey>): List<SecretBytes> {
        val ephemeral = ephemeralOf(attempt.recipient)
        return ephemeral?.let { found -> derivedKeys(attempt = attempt, keys = keys, ephemeral = found) }.orEmpty()
    }

    private suspend fun derivedKeys(attempt: Attempt, keys: List<CoseKey>, ephemeral: CoseKey): List<SecretBytes> {
        val algorithm = attempt.algorithm
        val matching = keys.filter { key -> KeyFit.canDerive(key, algorithm) && key.curve == ephemeral.curve }
        val derived = matching.mapNotNull { key ->
            attempted {
                derive(
                    privateKey = key.privateKey.sure(),
                    publicKey = ephemeral.publicKey.sure(),
                    recipient = attempt.recipient,
                    algorithm = algorithm,
                    algorithmId = Permissions.kdfAlgorithmId(algorithm = algorithm, content = attempt.content),
                    size = Permissions.derivedKeyBytes(algorithm = algorithm, content = attempt.content),
                )
            }
        }
        val wrap = algorithm.keyWrap ?: return derived
        val ciphertext = attempt.recipient.ciphertext ?: Bytes.Empty
        val size = Permissions.contentKeyBytes(attempt.content)
        return derived.mapNotNull { bytes ->
            val kek = bytes.use { material -> SecretKey.of(material) }
            val unwrapped = unwrapped(kek = kek, ciphertext = ciphertext, wrap = wrap, size = size)
            kek.destroy()
            unwrapped
        }
    }

    private fun ephemeralOf(recipient: CoseRecipient): CoseKey? {
        val item = recipient.protectedHeaders[HeaderLabels.EPHEMERAL_KEY]
            ?: recipient.unprotectedHeaders[HeaderLabels.EPHEMERAL_KEY]
        val map = (item ?: return null).mapOrNull().sure()
        val key = try {
            keyCodec.decode(map)
        } catch (ignored: CoseException) {
            null
        }
        return key?.takeIf { found -> found.privateKey == null }
    }

    private suspend fun unwrapped(
        kek: SecretKey,
        ciphertext: ByteString,
        wrap: KeyWrapAlgorithm,
        size: Int,
    ): SecretBytes? {
        val unwrapped = crypto.keyWraps.unwrap(kek = kek, wrapped = ciphertext, algorithm = wrap)
        val sized = unwrapped?.takeIf { found -> found.size == size }
        if (sized == null) unwrapped?.destroy()
        return sized
    }

    private inline fun <T> attempted(block: () -> T?): T? = try {
        block()
    } catch (ignored: CryptoException) {
        null
    }

    data class Created(val recipients: List<CoseRecipient>, val contentKey: SecretBytes)

    data class Candidates(val keys: List<SecretBytes>, val isPermitted: Boolean)

    private data class Attempt(
        val recipient: CoseRecipient,
        val algorithm: CoseAlgorithm,
        val content: CoseAlgorithm,
        val operation: CoseKeyOperation,
    )
}
