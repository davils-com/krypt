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

package com.davils.krypt.primitive.hash

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.primitive.internal.IncrementalDigest
import kotlinx.io.bytestring.ByteString

/**
 * Hashes input that arrives in pieces, such as a file read in chunks.
 *
 * A digester is not thread safe and can be finished once.
 *
 * @property algorithm the digest.
 * @since 1.0.0
 */
public class Digester internal constructor(
    public val algorithm: DigestAlgorithm,
    private val digest: IncrementalDigest,
) {
    private var isFinished = false

    /**
     * Adds [length] bytes of [bytes] from [offset] on.
     *
     * @param bytes the input.
     * @param offset where the input starts.
     * @param length how many bytes to add.
     * @throws IllegalStateException if the digester was finished.
     * @since 1.0.0
     */
    public fun update(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset) {
        check(!isFinished) { "The digester was finished already" }
        digest.update(bytes = bytes, offset = offset, length = length)
    }

    /**
     * Adds [bytes].
     *
     * @param bytes the input.
     * @throws IllegalStateException if the digester was finished.
     * @since 1.0.0
     */
    public fun update(bytes: ByteString) {
        update(bytes.toByteArray())
    }

    /**
     * Finishes the digest.
     *
     * @return the digest of everything added.
     * @throws IllegalStateException if the digester was finished already.
     * @since 1.0.0
     */
    public fun finish(): ByteString {
        check(!isFinished) { "The digester was finished already" }
        isFinished = true
        return ByteString(digest.finish())
    }

    /**
     * Shows the algorithm.
     *
     * @return the digester as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Digester(${algorithm.algorithmName}, finished=$isFinished)"
}
