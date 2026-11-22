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

package com.davils.krypt.keyset.kms

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.keyset.internal.Bytes
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

private const val VERSION: Byte = 1
private const val HEADER_BYTES: Int = 4
private const val LENGTH_SHIFT: Int = 8
private const val OCTET: Int = 0xFF
private const val MAXIMUM_WRAPPED_BYTES: Int = 4_096

/**
 * Envelope encryption: every message gets a fresh data key, which [kms] encrypts and which travels with the message.
 *
 * The key management service sees only data keys, never the data, so a remote KMS is called once per message and a
 * key encryption key can be rotated without touching the data. An envelope is a version byte, the index of the AEAD,
 * two bytes of the length of the encrypted data key, the encrypted data key, the nonce and the sealed data; the header
 * and the encrypted data key are authenticated with the data, and the associated data is bound to both the data and
 * the data key.
 *
 * The object holds no key and is safe to share between threads.
 *
 * @param crypto the primitives.
 * @param kms the service that encrypts the data keys.
 * @property algorithm the AEAD of the data; AES-256-GCM by default.
 * @constructor Seals with fresh data keys under [kms].
 * @since 1.0.0
 */
public class Envelopes(
    private val crypto: Crypto,
    private val kms: KeyManagementService,
    public val algorithm: AeadAlgorithm = AeadAlgorithm.Aes256Gcm,
) {
    /**
     * Seals [plaintext] in an envelope with a fresh data key.
     *
     * @param plaintext the data.
     * @param associatedData authenticated context; empty by default.
     * @return the envelope.
     * @throws IllegalStateException if [kms] returns an encrypted data key larger than 4096 bytes.
     * @since 1.0.0
     */
    public suspend fun seal(plaintext: ByteString, associatedData: ByteString = ByteString()): ByteString {
        val dataKey = crypto.keys.generateSecret(algorithm.keyBytes)
        val context = keyContext(associatedData)
        val wrapped = dataKey.export().use { secret -> kms.encrypt(plaintext = secret, associatedData = context) }
        check(
            wrapped.size <= MAXIMUM_WRAPPED_BYTES,
        ) { "The encrypted data key is larger than $MAXIMUM_WRAPPED_BYTES bytes" }
        val header = Bytes.concat(headerOf(wrapped.size), wrapped)
        val nonce = ByteString(crypto.environment.random.bytes(algorithm.nonceBytes))
        val sealed = crypto.aead.encrypt(
            key = dataKey,
            nonce = nonce,
            plaintext = plaintext,
            associatedData = Bytes.concat(header, associatedData),
            algorithm = algorithm,
        )
        dataKey.destroy()
        return Bytes.concat(header, nonce, sealed)
    }

    /**
     * Opens an envelope of [seal].
     *
     * @param envelope the envelope, possibly from an attacker.
     * @param associatedData the authenticated context it was sealed with.
     * @return the plaintext, or null if the envelope is malformed, was sealed with another AEAD or is not authentic.
     * @since 1.0.0
     */
    public suspend fun open(envelope: ByteString, associatedData: ByteString = ByteString()): ByteString? {
        val bytes = envelope.toByteArray()
        val wrappedSize = wrappedSizeOrNull(bytes)
        val headerSize = HEADER_BYTES + (wrappedSize ?: 0)
        val isComplete = wrappedSize != null && bytes.size >= headerSize + algorithm.nonceBytes
        val wrapped = isComplete.takeIf { complete -> complete }?.let {
            ByteString(data = bytes, startIndex = HEADER_BYTES, endIndex = headerSize)
        }
        val context = keyContext(associatedData)
        val dataKey = wrapped?.let { encrypted -> kms.decrypt(ciphertext = encrypted, associatedData = context) }
            ?: return null
        return dataKey.use { secret ->
            val key = SecretKey.of(secret.copy())
            val nonceEnd = headerSize + algorithm.nonceBytes
            val opened = crypto.aead.decrypt(
                key = key,
                nonce = ByteString(data = bytes, startIndex = headerSize, endIndex = nonceEnd),
                ciphertext = ByteString(data = bytes, startIndex = nonceEnd, endIndex = bytes.size),
                associatedData = Bytes.concat(
                    ByteString(data = bytes, startIndex = 0, endIndex = headerSize),
                    associatedData,
                ),
                algorithm = algorithm,
            )
            key.destroy()
            opened
        }
    }

    /**
     * Shows the service and the AEAD.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Envelopes($kms, ${algorithm.algorithmName})"

    private fun headerOf(wrappedSize: Int): ByteString = ByteString(
        VERSION,
        algorithm.ordinal.toByte(),
        (wrappedSize shr LENGTH_SHIFT).toByte(),
        (wrappedSize and OCTET).toByte(),
    )

    private fun wrappedSizeOrNull(bytes: ByteArray): Int? {
        val isHeader = bytes.size >= HEADER_BYTES && bytes[0] == VERSION && bytes[1] == algorithm.ordinal.toByte()
        val size = (
            (
                bytes
                    .getOrElse(
                        2,
                    ) { 0 }
                    .toInt() and OCTET
                ) shl LENGTH_SHIFT
            ) or (bytes.getOrElse(3) { 0 }.toInt() and OCTET)
        return size.takeIf { isHeader && size in 1..MAXIMUM_WRAPPED_BYTES }
    }

    private fun keyContext(associatedData: ByteString): ByteString =
        Bytes.concat(ByteString(VERSION, algorithm.ordinal.toByte()), associatedData)
}
