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

package com.davils.krypt.stream.internal

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.io.ByteSource
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.stream.StreamFailure
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.internal.StreamRefusal.Companion.ensure
import kotlinx.io.bytestring.ByteString

internal class SegmentWalk(crypto: Crypto, private val limits: StreamLimits) {
    var ciphertextBytes: Long = 0L
        private set

    val tree: MerkleTree = MerkleTree(crypto, DigestAlgorithm.Sha256)

    suspend fun walk(
        source: ByteSource,
        header: Header,
        visit: suspend (index: Long, isLast: Boolean, segment: ByteString) -> Unit,
    ) {
        val tag = header.suite.aead.tagBytes
        val chunks = Chunks(source, header.segmentSize + tag)
        var chunk = chunks.nextOrNull()
        while (chunk != null) {
            val (segment, isLast) = chunk
            ensure(tree.leaves < limits.maximumSegments && segment.size >= tag, StreamFailure.Malformed)
            visit(tree.leaves, isLast, segment)
            tree.add(segment)
            ciphertextBytes += segment.size
            chunk = chunks.nextOrNull()
        }
    }
}
