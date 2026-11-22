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

package com.davils.krypt.cose.internal

import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborSimple
import kotlinx.io.bytestring.ByteString

internal object Bodies {
    private const val DETACHED: String = "detached"

    fun headers(protectedEncoding: ByteString, unprotectedHeaders: CoseHeaders): List<CborItem> =
        listOf(CborBytes(protectedEncoding), unprotectedHeaders.parameters)

    fun optional(bytes: ByteString?): CborItem = bytes?.let { found -> CborBytes(found) } ?: CborSimple.Null

    fun size(bytes: ByteString?): String {
        if (bytes == null) return DETACHED
        return "${bytes.size} bytes"
    }

    fun describe(name: String, protectedHeaders: CoseHeaders, unprotectedHeaders: CoseHeaders, rest: String): String =
        "$name(protected=${protectedHeaders.parameters}, unprotected=${unprotectedHeaders.parameters}, $rest)"
}
