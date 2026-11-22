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

/**
 * A trusted record of the latest revision of every key set of a [KeysetVault], kept apart from the
 * [KeysetRepository], such as in a database with integrity guarantees or a monotonic counter of a hardware module;
 * with it, a vault refuses a key set that is older than the revision it records, so a key that was destroyed, rotated
 * away or deleted does not come back from a restored backup or a repository an attacker controls.
 *
 * The ledger sees only the names of the key sets, never their content. Its revisions only grow: a vault never lowers
 * or forgets one, and records a revision past the last one when it deletes a key set.
 *
 * @since 1.0.0
 */
public interface RevisionLedger {
    /**
     * Returns the latest revision recorded for [name].
     *
     * @param name the name of the key set.
     * @return the revision, or null if none was recorded.
     * @since 1.0.0
     */
    public suspend fun current(name: String): Long?

    /**
     * Records [revision] for [name] if the revision recorded now is [expected], atomically.
     *
     * @param name the name of the key set.
     * @param revision the new revision, greater than [expected].
     * @param expected the revision the caller read, or null if none was recorded.
     * @return true if it was recorded, false if another revision is recorded now.
     * @since 1.0.0
     */
    public suspend fun record(name: String, revision: Long, expected: Long?): Boolean
}
