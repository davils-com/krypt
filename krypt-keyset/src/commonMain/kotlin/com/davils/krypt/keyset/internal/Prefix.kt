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

package com.davils.krypt.keyset.internal

import com.davils.krypt.keyset.KeyId
import kotlinx.io.bytestring.ByteString

private const val VERSION: Byte = 1

internal data class Prefix(val id: KeyId, val rest: ByteString) {
    companion object {
        const val SIZE: Int = 1 + KeyId.SIZE

        fun of(id: KeyId): ByteString = Bytes.concat(ByteString(VERSION), id.bytes)

        fun parseOrNull(bytes: ByteString): Prefix? {
            val isPrefixed = bytes.size >= SIZE && bytes[0] == VERSION
            val array = bytes.toByteArray().takeIf { isPrefixed } ?: return null
            val id = KeyId.of(ByteString(data = array, startIndex = 1, endIndex = SIZE))
            return Prefix(id = id, rest = ByteString(data = array, startIndex = SIZE, endIndex = array.size))
        }
    }
}
