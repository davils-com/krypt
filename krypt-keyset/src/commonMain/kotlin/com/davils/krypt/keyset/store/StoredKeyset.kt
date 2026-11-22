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

package com.davils.krypt.keyset.store

import kotlinx.io.bytestring.ByteString

/**
 * An encrypted key set as a [KeysetRepository] keeps it, with the revision that guards concurrent changes.
 *
 * @property revision the revision, which grows by one with every change, starting at 1.
 * @property encrypted the encrypted key set.
 * @constructor Holds [encrypted] at [revision].
 * @throws IllegalArgumentException if [revision] is not positive.
 * @since 1.0.0
 */
public class StoredKeyset(public val revision: Long, public val encrypted: ByteString) {
    init {
        require(revision > 0) { "A revision starts at 1" }
    }

    /**
     * Compares the revision and the encrypted key set.
     *
     * @param other the other object.
     * @return true if [other] is the same stored key set.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is StoredKeyset && revision == other.revision && encrypted == other.encrypted

    /**
     * Hashes the revision.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = revision.hashCode()

    /**
     * Shows the revision and the size.
     *
     * @return the stored key set as text.
     * @since 1.0.0
     */
    override fun toString(): String = "StoredKeyset(revision=$revision, bytes=${encrypted.size})"
}
