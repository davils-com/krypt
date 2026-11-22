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
 * Where encrypted key sets are kept, implemented by the application over its database, secret store or object store;
 * krypt never writes a file itself.
 *
 * A repository sees encrypted key sets only. It must store atomically and compare the revision before it stores, so
 * that two processes that rotate the same key set at once never lose a key.
 *
 * @since 1.0.0
 */
public interface KeysetRepository {
    /**
     * Loads the key set stored under [name].
     *
     * @param name the name.
     * @return the stored key set, or null if there is none.
     * @since 1.0.0
     */
    public suspend fun load(name: String): StoredKeyset?

    /**
     * Stores [keyset] under [name] if the revision stored now is [expectedRevision].
     *
     * @param name the name.
     * @param keyset the key set to store, whose revision is one more than [expectedRevision].
     * @param expectedRevision the revision the caller read, or null if it expects no key set under [name].
     * @return true if it was stored, false if another revision is stored now.
     * @since 1.0.0
     */
    public suspend fun store(name: String, keyset: StoredKeyset, expectedRevision: Long?): Boolean

    /**
     * Deletes the key set stored under [name], so that nothing it protected can be decrypted again.
     *
     * @param name the name.
     * @return true if a key set was deleted.
     * @since 1.0.0
     */
    public suspend fun delete(name: String): Boolean
}
