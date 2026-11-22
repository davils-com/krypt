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

import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import kotlinx.io.bytestring.ByteString

internal fun CborItem.longOrNull(): Long? = integerOrNull()?.toLongOrNull()

internal fun CborMap.bytesAt(label: Long): ByteString? = get(label)?.bytesOrNull()

internal fun CborMap.longAt(label: Long): Long? = get(label)?.longOrNull()

internal fun CborMap.itemsAt(label: Long): List<CborItem>? = get(label)?.itemsOrNull()

internal fun labelOf(value: Long): CborInteger = CborInteger.of(value)

internal fun bytesOf(value: ByteString): CborBytes = CborBytes(value)

internal fun <T : Any> T?.sure(): T = listOfNotNull(this).single()
