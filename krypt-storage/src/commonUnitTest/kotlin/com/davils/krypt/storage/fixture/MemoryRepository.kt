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

package com.davils.krypt.storage.fixture

import com.davils.krypt.keyset.store.KeysetRepository
import com.davils.krypt.keyset.store.StoredKeyset

internal class MemoryRepository : KeysetRepository {
    val stored: MutableMap<String, StoredKeyset> = mutableMapOf()

    override suspend fun load(name: String): StoredKeyset? = stored[name]

    override suspend fun store(name: String, keyset: StoredKeyset, expectedRevision: Long?): Boolean {
        val isExpected = stored[name]?.revision == expectedRevision
        if (isExpected) stored[name] = keyset
        return isExpected
    }

    override suspend fun delete(name: String): Boolean = stored.remove(name) != null
}
