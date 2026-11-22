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

package com.davils.krypt.core

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import kotlinx.io.bytestring.ByteString

private const val DESTROYED_MESSAGE: String = "The secret was destroyed, so its bytes cannot be read any more"

/**
 * Secret bytes, such as the bytes of a symmetric key, a seed or a derived secret, that krypt wipes on [destroy].
 *
 * A secret owns its bytes: every factory copies what it is given or takes over an array nobody else holds, and
 * [reveal] lends the bytes only for the duration of a block. [destroy] (or the end of [use]) overwrites them with
 * zeros, after
 * which every read throws. The text of a secret never shows its bytes, [equals] compares in constant time, and
 * [hashCode] depends on the size alone, so a secret in a hash-based collection leaks nothing through its bucket.
 *
 * Wiping is best effort: a copy the platform made on its own, such as the key schedule of a JCA cipher, a moved array
 * of a garbage collector or a key imported into WebCrypto, is out of reach of krypt. A secret is not thread safe;
 * [destroy] must not race with [reveal].
 *
 * @since 1.0.0
 */
public class SecretBytes private constructor(initial: ByteArray) {
    private var bytes: ByteArray? = initial

    /**
     * The number of bytes, which stays readable after [destroy].
     *
     * @since 1.0.0
     */
    public val size: Int = initial.size

    /**
     * Tells whether [destroy] wiped the bytes.
     *
     * @since 1.0.0
     */
    public val isDestroyed: Boolean get() = bytes == null

    /**
     * Lends the bytes to [block]. The array is the secret itself: [block] must neither change nor keep it.
     *
     * @param R the result of [block].
     * @param block reads the bytes.
     * @return what [block] returns.
     * @throws IllegalStateException if the secret was destroyed.
     * @since 1.0.0
     */
    public inline fun <R> reveal(block: (ByteArray) -> R): R = block(revealed())

    @PublishedApi
    internal fun revealed(): ByteArray = checkNotNull(bytes) { DESTROYED_MESSAGE }

    /**
     * Copies the bytes into a new secret that is destroyed on its own.
     *
     * @return the copy.
     * @throws IllegalStateException if the secret was destroyed.
     * @since 1.0.0
     */
    public fun copy(): SecretBytes = SecretBytes(checkNotNull(bytes) { DESTROYED_MESSAGE }.copyOf())

    /**
     * Copies the first [length] bytes into a new secret.
     *
     * @param length the number of bytes, from 0 to [size].
     * @return the prefix.
     * @throws IllegalArgumentException if [length] is negative or larger than [size].
     * @throws IllegalStateException if the secret was destroyed.
     * @since 1.0.0
     */
    public fun prefix(length: Int): SecretBytes {
        require(length in 0..size) { "A prefix of $length bytes does not fit into a secret of $size bytes" }
        return SecretBytes(checkNotNull(bytes) { DESTROYED_MESSAGE }.copyOf(length))
    }

    /**
     * Overwrites the bytes with zeros and forgets them. Destroying twice does nothing.
     *
     * @since 1.0.0
     */
    public fun destroy() {
        bytes?.fill(0)
        bytes = null
    }

    /**
     * Runs [block] with this secret and destroys the secret afterwards, also when [block] throws.
     *
     * @param R the result of [block].
     * @param block uses the secret.
     * @return what [block] returns.
     * @since 1.0.0
     */
    public inline fun <R> use(block: (SecretBytes) -> R): R {
        try {
            return block(this)
        } finally {
            destroy()
        }
    }

    /**
     * Compares the bytes with those of [other] in constant time. A destroyed secret equals only itself.
     *
     * @param other the other object.
     * @return true if [other] is a secret with the same bytes.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        val mine = bytes ?: return false
        return other is SecretBytes &&
            other.bytes?.let { theirs ->
                ConstantTime.equals(
                    first = mine,
                    second = theirs,
                )
            } == true
    }

    /**
     * Returns a hash of the size alone, so the bytes never decide a bucket.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = size

    /**
     * Shows the size and whether the secret was destroyed, never the bytes.
     *
     * @return the secret as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SecretBytes(size=$size, bytes=${SafeText.REDACTED}, destroyed=$isDestroyed)"

    /**
     * The factories of a secret.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Copies [bytes] into a new secret; the caller still owns [bytes] and should wipe it.
         *
         * @param bytes the bytes.
         * @return the secret.
         * @since 1.0.0
         */
        public fun copyOf(bytes: ByteArray): SecretBytes = SecretBytes(bytes.copyOf())

        /**
         * Copies the bytes of [bytes] into a new secret.
         *
         * @param bytes the bytes.
         * @return the secret.
         * @since 1.0.0
         */
        public fun copyOf(bytes: ByteString): SecretBytes = SecretBytes(bytes.toByteArray())

        /**
         * Takes over [bytes] without copying it: the caller hands over the only reference and never touches the
         * array again, because [destroy] wipes it.
         *
         * @param bytes the bytes.
         * @return the secret.
         * @since 1.0.0
         */
        public fun adopt(bytes: ByteArray): SecretBytes = SecretBytes(bytes)

        /**
         * Creates a secret of [size] random bytes from [random].
         *
         * @param size the number of bytes, at least 1.
         * @param random the randomness.
         * @return the secret.
         * @throws IllegalArgumentException if [size] is below 1.
         * @since 1.0.0
         */
        public fun random(size: Int, random: RandomSource): SecretBytes {
            require(size >= 1) { "A random secret needs at least one byte, not $size" }
            val bytes = ByteArray(size)
            random.fill(bytes)
            return SecretBytes(bytes)
        }
    }
}
