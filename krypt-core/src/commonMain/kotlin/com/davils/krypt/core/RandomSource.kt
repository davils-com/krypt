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

package com.davils.krypt.core

import com.davils.krypt.core.internal.fillSecurely

/**
 * Where the random bytes of keys, nonces, salts and serial numbers come from.
 *
 * Every random value krypt creates is drawn from the [Environment.random] of the operation, which is [Secure] unless
 * the caller hands in another source, such as a FIPS DRBG of its provider on the JVM or a deterministic source in a
 * test. A source must be safe to call from several threads at once.
 *
 * @since 1.0.0
 */
public fun interface RandomSource {
    /**
     * Fills [target] with random bytes.
     *
     * @param target the array to fill.
     * @since 1.0.0
     */
    public fun fill(target: ByteArray)

    /**
     * Returns [count] random bytes.
     *
     * @param count the number of bytes, at least 0.
     * @return the bytes.
     * @throws IllegalArgumentException if [count] is negative.
     * @since 1.0.0
     */
    public fun bytes(count: Int): ByteArray {
        require(count >= 0) { "A negative number of random bytes cannot be drawn: $count" }
        val target = ByteArray(count)
        fill(target)
        return target
    }

    /**
     * The secure randomness of the platform.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The secure randomness of the platform: a `SecureRandom` of the JVM's default provider, or
         * `crypto.getRandomValues` of the JavaScript host on Wasm.
         *
         * @since 1.0.0
         */
        public val Secure: RandomSource = RandomSource { target -> fillSecurely(target) }
    }
}
