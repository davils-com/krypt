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

package com.davils.krypt.stream

import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.stream.manifest.Manifest
import com.davils.krypt.stream.manifest.ManifestKind
import kotlinx.io.bytestring.ByteString

/**
 * What identifies a container without its keys: the digest of its header and the Merkle root of its encrypted
 * segments, as written by encryption or found by reading.
 *
 * Signing its [manifest] signs the whole container; the signature can be checked by anyone who holds the container,
 * without decrypting it.
 *
 * @property headerDigest the SHA-256 digest of the header.
 * @property segmentSize the size of a segment of plaintext.
 * @property segments the number of segments.
 * @property ciphertextBytes the size of the container.
 * @property plaintextBytes the size of the plaintext.
 * @property root the SHA-256 Merkle root of the encrypted segments.
 * @since 1.0.0
 */
public class ContainerSeal internal constructor(
    public val headerDigest: ByteString,
    public val segmentSize: Int,
    public val segments: Long,
    public val ciphertextBytes: Long,
    public val plaintextBytes: Long,
    public val root: ByteString,
) {
    /**
     * The manifest of the container, for signing it.
     *
     * @since 1.0.0
     */
    public val manifest: Manifest
        get() = Manifest(
            kind = ManifestKind.Container,
            digest = DigestAlgorithm.Sha256,
            segmentSize = segmentSize,
            length = ciphertextBytes,
            segments = segments,
            root = root,
            context = headerDigest,
        )

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same seal.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is ContainerSeal &&
        manifest == other.manifest &&
        plaintextBytes == other.plaintextBytes

    /**
     * Hashes the root.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = root.hashCode()

    /**
     * Shows the sizes and the root.
     *
     * @return the seal as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "ContainerSeal(segments=$segments, ciphertextBytes=$ciphertextBytes, plaintextBytes=$plaintextBytes, " +
            "root=${Hex.encode(root)})"
}
