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

package com.davils.krypt.stream.manifest

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.encoding.Hex
import kotlinx.io.bytestring.ByteString

/**
 * A short description of large data that can be signed instead of the data: its length, the size of its segments and
 * the Merkle root of the segments, with leaves and nodes hashed apart as in RFC 6962.
 *
 * @property kind what the manifest covers.
 * @property digest the digest of the Merkle tree.
 * @property segmentSize the size of a segment.
 * @property length the number of bytes covered.
 * @property segments the number of segments.
 * @property root the Merkle root.
 * @property context what else the manifest binds, such as the digest of the header of a container; may be empty.
 * @constructor Describes data with [root].
 * @throws IllegalArgumentException if [digest] is not SHA-256, SHA-384 or SHA-512, [root] does not fit it, or a size
 *   is negative.
 * @since 1.0.0
 */
public class Manifest(
    public val kind: ManifestKind,
    public val digest: DigestAlgorithm,
    public val segmentSize: Int,
    public val length: Long,
    public val segments: Long,
    public val root: ByteString,
    public val context: ByteString = ByteString(),
) {
    init {
        require(digest in DIGESTS) { "A manifest uses SHA-256, SHA-384 or SHA-512" }
        require(root.size == digest.outputBytes) { "A root of ${digest.algorithmName} has ${digest.outputBytes} bytes" }
        require(segmentSize > 0 && length >= 0 && segments >= 0) { "The sizes of a manifest are not negative" }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] describes the same data.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is Manifest &&
        listOf(kind, digest, segmentSize, length, segments, root, context) ==
        listOf(other.kind, other.digest, other.segmentSize, other.length, other.segments, other.root, other.context)

    /**
     * Hashes the root.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = root.hashCode()

    /**
     * Shows every property.
     *
     * @return the manifest as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Manifest($kind, ${digest.algorithmName}, length=$length, segments=$segments, " +
        "root=${Hex.encode(root)})"

    internal companion object {
        val DIGESTS: Set<DigestAlgorithm> = setOf(
            DigestAlgorithm.Sha256,
            DigestAlgorithm.Sha384,
            DigestAlgorithm.Sha512,
        )
    }
}
