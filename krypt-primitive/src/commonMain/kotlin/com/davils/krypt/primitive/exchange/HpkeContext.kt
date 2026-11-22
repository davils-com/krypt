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

package com.davils.krypt.primitive.exchange

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.internal.HpkeCipher
import com.davils.krypt.primitive.internal.Labels
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.bytestring.ByteString

private const val LONG_BYTES: Int = 8
private const val BYTE_BITS: Int = 8

/**
 * An HPKE encryption context of RFC 9180: a key and a base nonce, whose sequence number advances with every message,
 * and an exporter secret.
 *
 * A context is thread safe: messages are numbered in the order they are sealed or opened. A context of a sender only
 * seals and one of a recipient only opens. [destroy] wipes the keys.
 *
 * @property suite the cipher suite.
 * @since 1.0.0
 */
public class HpkeContext internal constructor(
    private val crypto: Crypto,
    public val suite: HpkeSuite,
    private val cipher: HpkeCipher?,
    private val baseNonce: ByteArray,
    private val exporterSecret: SecretBytes,
    private val labels: Labels,
) {
    private val lock = Mutex()
    private var sequence = 0L

    /**
     * Encrypts the next message.
     *
     * @param plaintext the message.
     * @param associatedData authenticated context; empty by default.
     * @return the ciphertext.
     * @throws IllegalStateException if the suite exports only, the context was destroyed or the sequence ran out.
     * @since 1.0.0
     */
    public suspend fun seal(plaintext: ByteString, associatedData: ByteString = ByteString()): ByteString = lock
        .withLock {
            val sealing = checkNotNull(cipher) { "An export-only context seals nothing" }
            val sealed = crypto.aead.encrypt(
                key = sealing.key,
                nonce = nextNonce(),
                plaintext = plaintext,
                associatedData = associatedData,
                algorithm = sealing.aead,
            )
            sealed
        }

    /**
     * Decrypts the next message; a message that does not decrypt does not advance the sequence.
     *
     * @param ciphertext the ciphertext.
     * @param associatedData authenticated context; empty by default.
     * @return the plaintext, or null if the message is not authentic.
     * @throws IllegalStateException if the suite exports only, the context was destroyed or the sequence ran out.
     * @since 1.0.0
     */
    public suspend fun open(ciphertext: ByteString, associatedData: ByteString = ByteString()): ByteString? = lock
        .withLock {
            val opening = checkNotNull(cipher) { "An export-only context opens nothing" }
            val opened = crypto.aead.decrypt(
                key = opening.key,
                nonce = nonceAt(sequence),
                ciphertext = ciphertext,
                associatedData = associatedData,
                algorithm = opening.aead,
            )
            opened?.also { sequence += 1 }
        }

    /**
     * Exports a secret bound to this context and [exporterContext].
     *
     * @param exporterContext what the secret is for.
     * @param length the number of bytes.
     * @return the secret.
     * @throws IllegalStateException if the context was destroyed.
     * @since 1.0.0
     */
    public suspend fun export(exporterContext: ByteString, length: Int): SecretBytes =
        labels.expand(prk = exporterSecret, label = "sec", info = exporterContext, length = length)

    /**
     * Wipes the key, the nonce and the exporter secret.
     *
     * @since 1.0.0
     */
    public fun destroy() {
        cipher?.run { key.destroy() }
        baseNonce.fill(0)
        exporterSecret.destroy()
    }

    /**
     * Shows the suite and the sequence number.
     *
     * @return the context as text.
     * @since 1.0.0
     */
    override fun toString(): String = "HpkeContext($suite, sequence=$sequence)"

    private fun nextNonce(): ByteString {
        val nonce = nonceAt(sequence)
        sequence += 1
        return nonce
    }

    private fun nonceAt(number: Long): ByteString {
        val nonce = baseNonce.copyOf()
        for (index in 0 until LONG_BYTES) {
            val position = nonce.size - 1 - index
            nonce[position] = (nonce[position].toInt() xor (number shr index * BYTE_BITS).toInt()).toByte()
        }
        return ByteString(nonce)
    }
}
