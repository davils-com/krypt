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

package com.davils.krypt.cms.fixture

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.readRemaining
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.indexOf

private const val INDEFINITE: Int = 0x80
private const val SEQUENCE: Int = 0x30

internal fun replaced(encoded: ByteString, old: ByteString, new: ByteString): ByteString {
    val index = encoded.indexOf(old)
    check(index >= 0) { "The bytes to replace are not in the encoding" }
    val head = encoded.substring(startIndex = 0, endIndex = index)
    val tail = encoded.substring(startIndex = index + old.size, endIndex = encoded.size)
    return ByteString(head.toByteArray() + new.toByteArray() + tail.toByteArray())
}

internal fun flipped(bytes: ByteString): ByteString {
    val array = bytes.toByteArray()
    array[array.size - 1] = (array[array.size - 1].toInt() xor 1).toByte()
    return ByteString(array)
}

internal fun truncated(encoded: ByteString): ByteString = encoded.substring(startIndex = 0, endIndex = encoded.size - 1)

internal fun trailing(encoded: ByteString): ByteString = ByteString(encoded.toByteArray() + byteArrayOf(0))

internal fun indefinite(encoded: ByteString): ByteString {
    val content = checkNotNull(Der.decodeOrNull(encoded) { readElement() }).content
    val head = byteArrayOf(SEQUENCE.toByte(), INDEFINITE.toByte())
    return ByteString(head + content.toByteArray() + byteArrayOf(0, 0))
}

internal fun children(encoded: ByteString): List<DerElement> =
    checkNotNull(Der.decodeOrNull(encoded) { readSequence { readRemaining() } })
