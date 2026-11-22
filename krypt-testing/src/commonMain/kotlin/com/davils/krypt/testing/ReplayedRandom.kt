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

package com.davils.krypt.testing

import com.davils.krypt.core.RandomSource
import kotlinx.io.bytestring.ByteString
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * A [RandomSource] that hands out the given [bytes] in order, for known-answer tests that fix an ephemeral key, a
 * nonce or a salt.
 *
 * Each draw takes the next bytes; a draw past the end throws, so a test notices when the code under test draws more
 * than the vector holds. The source is safe to share between threads.
 *
 * @property bytes the bytes to hand out.
 * @constructor Hands out [bytes].
 * @since 1.0.0
 */
@OptIn(ExperimentalAtomicApi::class)
public class ReplayedRandom(public val bytes: ByteString) : RandomSource {
    private val position = AtomicInt(0)

    /**
     * How many bytes are left.
     *
     * @since 1.0.0
     */
    public val remaining: Int get() = bytes.size - position.load()

    /**
     * Fills [target] with the next bytes.
     *
     * @param target the array to fill.
     * @throws IllegalStateException if fewer bytes are left than [target] needs.
     * @since 1.0.0
     */
    override fun fill(target: ByteArray) {
        val start = position.fetchAndAdd(target.size)
        val end = start + target.size
        check(end <= bytes.size) { "The replayed randomness is exhausted: ${target.size} bytes wanted at $start" }
        bytes.copyInto(destination = target, startIndex = start, endIndex = end)
    }

    /**
     * Shows how many bytes are left.
     *
     * @return the source as text.
     * @since 1.0.0
     */
    override fun toString(): String = "ReplayedRandom(remaining=$remaining)"
}
