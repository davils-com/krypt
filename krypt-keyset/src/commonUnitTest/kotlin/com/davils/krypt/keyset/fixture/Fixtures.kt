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

import com.davils.krypt.core.audit.AuditEntry
import com.davils.krypt.core.environment
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

internal val crypto: Crypto = Crypto()

internal val keysets: Keysets = Keysets(crypto)

internal fun utf8(text: String): ByteString = ByteString(text.encodeToByteArray())

internal fun auditedKeysets(entries: MutableList<AuditEntry>): Keysets =
    Keysets(Crypto(environment { audit({ entry -> entries += entry }) }))

internal fun refusingKeysets(): Keysets =
    Keysets(Crypto(environment { audit({ _ -> error("the audit store is down") }, required = true) }))

internal fun flipped(bytes: ByteString, index: Int): ByteString {
    val array = bytes.toByteArray()
    array[index] = (array[index].toInt() xor 1).toByte()
    return ByteString(array)
}
