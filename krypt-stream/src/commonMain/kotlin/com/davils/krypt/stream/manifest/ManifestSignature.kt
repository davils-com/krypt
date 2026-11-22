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

import kotlinx.io.bytestring.ByteString

/**
 * One signature of a [SignedManifest].
 *
 * @property signature the signature of a key set, which names its key.
 * @property countersigns the index of the signature this one countersigns, or null if it signs the manifest.
 * @property timestamp an opaque time-stamp token over the signature, such as one of RFC 3161, or null; krypt never
 *   verifies it, so a caller that relies on it verifies it and its message imprint itself.
 * @constructor Holds [signature].
 * @throws IllegalArgumentException if [countersigns] is negative.
 * @since 1.0.0
 */
public class ManifestSignature(
    public val signature: ByteString,
    public val countersigns: Int? = null,
    public val timestamp: ByteString? = null,
) {
    init {
        require((countersigns ?: 0) >= 0) { "A countersignature names a signature from 0" }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same signature.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is ManifestSignature &&
        listOf(signature, countersigns, timestamp) == listOf(other.signature, other.countersigns, other.timestamp)

    /**
     * Hashes the signature.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = signature.hashCode()

    /**
     * Shows the size and the target.
     *
     * @return the signature as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "ManifestSignature(bytes=${signature.size}, countersigns=${countersigns ?: NONE}, timestamped=${timestamp != null})"

    private companion object {
        const val NONE: String = "none"
    }
}
