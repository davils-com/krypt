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

package com.davils.krypt.keystore.fixture

import com.davils.krypt.keystore.material.MaterialRead
import com.davils.krypt.keystore.material.MaterialRef
import com.davils.krypt.keystore.material.MaterialSink
import com.davils.krypt.keystore.material.MaterialSource
import kotlinx.io.bytestring.ByteString

internal class MemoryMaterial : MaterialSource, MaterialSink {
    val stored: MutableMap<MaterialRef, ByteString> = mutableMapOf()

    val secrets: MutableSet<MaterialRef> = mutableSetOf()

    var isUnavailable: Boolean = false

    override suspend fun read(ref: MaterialRef, maximumBytes: Int): MaterialRead {
        if (isUnavailable) return MaterialRead.Unavailable
        return stored[ref]?.let { bytes -> MaterialRead.Found(bytes) } ?: MaterialRead.Missing
    }

    override suspend fun write(ref: MaterialRef, bytes: ByteString, isSecret: Boolean) {
        stored[ref] = bytes
        if (isSecret) secrets += ref
    }
}
