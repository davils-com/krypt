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
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

private val LEAF: ByteString = ByteString(0)
private val NODE: ByteString = ByteString(1)

internal class MerkleTree(private val crypto: Crypto, private val algorithm: DigestAlgorithm) {
    private val hashes = mutableListOf<ByteString>()
    private val heights = mutableListOf<Int>()

    var leaves: Long = 0L
        private set

    suspend fun add(data: ByteString) {
        hashes += crypto.digests.digest(Octets.concat(LEAF, data), algorithm)
        heights += 0
        leaves++
        while (heights.size >= 2 && heights[heights.size - 1] == heights[heights.size - 2]) {
            val right = hashes.removeAt(hashes.size - 1)
            val left = hashes.removeAt(hashes.size - 1)
            val height = heights.removeAt(heights.size - 1)
            heights.removeAt(heights.size - 1)
            hashes += node(left = left, right = right)
            heights += height + 1
        }
    }

    suspend fun root(): ByteString {
        var root = hashes.lastOrNull() ?: return crypto.digests.digest(ByteString(), algorithm)
        for (index in hashes.size - 2 downTo 0) root = node(left = hashes[index], right = root)
        return root
    }

    private suspend fun node(left: ByteString, right: ByteString): ByteString =
        crypto.digests.digest(Octets.concat(NODE, left, right), algorithm)
}
