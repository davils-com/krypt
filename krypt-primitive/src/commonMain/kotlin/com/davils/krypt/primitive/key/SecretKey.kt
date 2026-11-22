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

package com.davils.krypt.primitive.key

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.core.SecretBytes

private const val BYTE_BITS: Int = 8

/**
 * A symmetric key: the secret bytes of an AEAD, a MAC, a key wrap or a key derivation.
 *
 * The key owns its bytes and wipes them on [destroy]. A symmetric key is safe to use from several threads, but
 * [destroy] must not race with an operation.
 *
 * @since 1.0.0
 */
public class SecretKey internal constructor(private val material: SecretBytes) {
    internal var handle: Any? = null

    /**
     * The size of the key in bits.
     *
     * @since 1.0.0
     */
    public val bits: Int = material.size * BYTE_BITS

    /**
     * Tells whether [destroy] was called.
     *
     * @since 1.0.0
     */
    public val isDestroyed: Boolean get() = material.isDestroyed

    /**
     * Copies the key bytes, to store the key wrapped or to hand it to another system.
     *
     * @return a copy the caller owns and should destroy.
     * @throws IllegalStateException if the key was destroyed.
     * @since 1.0.0
     */
    public fun export(): SecretBytes = material.copy()

    internal inline fun <R> reveal(block: (ByteArray) -> R): R = material.reveal(block)

    /**
     * Wipes the key bytes and forgets the platform handle. Destroying twice does nothing.
     *
     * @since 1.0.0
     */
    public fun destroy() {
        material.destroy()
        handle = null
    }

    /**
     * Compares the key bytes in constant time.
     *
     * @param other the other object.
     * @return true if [other] is a key with the same bytes.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is SecretKey && material == other.material

    /**
     * Returns a hash of the size alone.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = bits

    /**
     * Shows the size, never the key.
     *
     * @return the key as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SecretKey(bits=$bits, key=${SafeText.REDACTED}, destroyed=$isDestroyed)"

    /**
     * The factories of a symmetric key.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The fewest bytes of a symmetric key: 16, the 128 bits every profile demands at least.
         *
         * @since 1.0.0
         */
        public const val MINIMUM_BYTES: Int = 16

        /**
         * Copies [bytes] into a new key; the caller still owns [bytes].
         *
         * @param bytes the key bytes, at least 16.
         * @return the key.
         * @throws IllegalArgumentException if [bytes] has fewer than 16 bytes.
         * @since 1.0.0
         */
        public fun of(bytes: SecretBytes): SecretKey {
            require(
                bytes.size >= MINIMUM_BYTES,
            ) { "A symmetric key has at least $MINIMUM_BYTES bytes, not ${bytes.size}" }
            return SecretKey(bytes.copy())
        }
    }
}
