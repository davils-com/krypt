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

package com.davils.krypt.storage.blob

/**
 * A trusted record of the current version of every object, kept apart from the [BlobStore], such as in a database
 * with integrity guarantees; with it, an [EncryptedBlobStore] detects an old version that was put back.
 *
 * The ledger sees only blinded keys; the version of a name is the highest version recorded under the blinded keys of
 * all enabled keys of the names key set. A version is recorded under the blinded key of the primary key before the
 * object is written, so an object whose write failed reads as a rollback until it is put again. A deletion records a
 * version past the deleted one instead of forgetting it, so the versions of a name only grow.
 *
 * @since 1.0.0
 */
public interface VersionLedger {
    /**
     * Returns the current version of [key].
     *
     * @param key the blinded key.
     * @return the version, or null if the object has none.
     * @since 1.0.0
     */
    public suspend fun current(key: String): Long?

    /**
     * Records [version] for [key] if the current version is [expected], atomically.
     *
     * @param key the blinded key.
     * @param version the new version.
     * @param expected the version the caller read, or null for a new object.
     * @return true if it was recorded, false if another version is current.
     * @since 1.0.0
     */
    public suspend fun record(key: String, version: Long, expected: Long?): Boolean

    /**
     * Forgets [key] once its object was moved to the blinded key of another key of the names key set, whose recorded
     * version is at least as high.
     *
     * @param key the blinded key.
     * @since 1.0.0
     */
    public suspend fun forget(key: String)
}
