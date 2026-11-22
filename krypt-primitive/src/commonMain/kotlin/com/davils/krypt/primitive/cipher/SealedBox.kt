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

package com.davils.krypt.primitive.cipher

import com.davils.krypt.core.algorithm.AeadAlgorithm
import kotlinx.io.bytestring.ByteString

/**
 * The result of [Aeads.seal]: the nonce and the ciphertext with its authentication tag.
 *
 * @property nonce the nonce, as long as the algorithm demands.
 * @property ciphertext the ciphertext followed by the tag.
 * @since 1.0.0
 */
public class SealedBox(public val nonce: ByteString, public val ciphertext: ByteString) {
    /**
     * The nonce followed by the ciphertext, the form most protocols store.
     *
     * @since 1.0.0
     */
    public val encoded: ByteString get() = ByteString(nonce.toByteArray() + ciphertext.toByteArray())

    /**
     * Compares nonce and ciphertext.
     *
     * @param other the other object.
     * @return true if [other] is the same box.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is SealedBox && nonce == other.nonce && ciphertext == other.ciphertext

    /**
     * Hashes nonce and ciphertext.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(nonce, ciphertext).hashCode()

    /**
     * Shows the sizes.
     *
     * @return the box as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SealedBox(nonce=${nonce.size}, ciphertext=${ciphertext.size})"

    /**
     * The factory of a box from its encoding.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Splits [encoded], a nonce followed by a ciphertext, for [algorithm].
         *
         * @param encoded the nonce and the ciphertext.
         * @param algorithm the AEAD, which decides the length of the nonce and the tag.
         * @return the box, or null if [encoded] is shorter than a nonce and a tag.
         * @since 1.0.0
         */
        public fun decodeOrNull(encoded: ByteString, algorithm: AeadAlgorithm): SealedBox? {
            val isLongEnough = encoded.size >= algorithm.nonceBytes + algorithm.tagBytes
            val bytes = encoded.toByteArray().takeIf { isLongEnough } ?: return null
            return SealedBox(
                nonce = ByteString(data = bytes, startIndex = 0, endIndex = algorithm.nonceBytes),
                ciphertext = ByteString(data = bytes, startIndex = algorithm.nonceBytes, endIndex = bytes.size),
            )
        }
    }
}
