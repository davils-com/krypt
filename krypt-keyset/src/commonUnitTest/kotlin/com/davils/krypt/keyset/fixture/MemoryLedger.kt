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

package com.davils.krypt.keyset.fixture

import com.davils.krypt.keyset.store.RevisionLedger

internal class MemoryLedger : RevisionLedger {
    val revisions: MutableMap<String, Long> = mutableMapOf()
    var isFailing: Boolean = false
    var isRefusing: Boolean = false

    override suspend fun current(name: String): Long? {
        check(!isFailing) { "the ledger is down" }
        return revisions[name]
    }

    override suspend fun record(name: String, revision: Long, expected: Long?): Boolean {
        val isExpected = revisions[name] == expected && !isRefusing
        if (isExpected) revisions[name] = revision
        return isExpected
    }
}
