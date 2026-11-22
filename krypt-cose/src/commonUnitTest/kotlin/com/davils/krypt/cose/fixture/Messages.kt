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

package com.davils.krypt.cose.fixture

import com.davils.krypt.cose.CoseMessageType
import com.davils.krypt.cose.CoseRecipient
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborSimple
import com.davils.krypt.cose.cbor.CborTag
import kotlinx.io.bytestring.ByteString

internal fun label(value: Long): CborItem = CborInteger.of(value)

internal fun headers(vararg entries: Pair<Long, CborItem>): CborMap =
    CborMap(entries.map { (key, value) -> label(key) to value })

internal fun protectedOf(map: CborMap): CborItem =
    CborBytes(Cbor.encode(map).takeUnless { map.size == 0 } ?: ByteString())

internal fun optional(bytes: ByteString?): CborItem = bytes?.let { found -> CborBytes(found) } ?: CborSimple.Null

internal fun tagged(type: CoseMessageType, vararg items: CborItem): ByteString =
    Cbor.encode(CborTag(number = type.tag, content = CborArray(items.toList())))

internal fun recipientItem(recipient: CoseRecipient): CborItem = CborArray(recipient.body())

internal fun recipientItem(protectedMap: CborMap, unprotectedMap: CborMap, ciphertext: ByteString?): CborItem =
    CborArray.of(protectedOf(protectedMap), unprotectedMap, optional(ciphertext))
