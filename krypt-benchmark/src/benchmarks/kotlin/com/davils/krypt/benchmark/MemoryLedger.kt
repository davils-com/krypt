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

package com.davils.krypt.benchmark

import com.davils.krypt.storage.blob.VersionLedger

internal class MemoryLedger : VersionLedger {
    private val versions = mutableMapOf<String, Long>()

    override suspend fun current(key: String): Long? = versions[key]

    override suspend fun record(key: String, version: Long, expected: Long?): Boolean {
        val isExpected = versions[key] == expected
        if (isExpected) versions[key] = version
        return isExpected
    }

    override suspend fun forget(key: String) {
        versions.remove(key)
    }
}
