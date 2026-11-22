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

package com.davils.krypt.primitive.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import kotlinx.io.bytestring.ByteString

internal object EcdsaSignatures {
    fun derOf(raw: ByteArray): ByteArray {
        val half = raw.size / 2
        val r = DerInteger.ofMagnitude(ByteString(data = raw, startIndex = 0, endIndex = half))
        val s = DerInteger.ofMagnitude(ByteString(data = raw, startIndex = half, endIndex = raw.size))
        val encoded = Der.encode {
            sequence {
                integer(r)
                integer(s)
            }
        }
        return encoded.toByteArray()
    }

    fun rawOf(der: ByteArray, fieldBytes: Int): ByteArray? {
        val pair = Der.decodeOrNull(ByteString(der)) { readSequence { readInteger() to readInteger() } }
        val r = pair?.first?.takeUnless { value -> value.isNegative }?.magnitude()
        val s = pair?.second?.takeUnless { value -> value.isNegative }?.magnitude()
        val isFitting = r != null && s != null && r.size <= fieldBytes && s.size <= fieldBytes
        if (!isFitting) return null
        val raw = ByteArray(fieldBytes * 2)
        r.copyInto(destination = raw, destinationOffset = fieldBytes - r.size)
        s.copyInto(destination = raw, destinationOffset = fieldBytes * 2 - s.size)
        return raw
    }
}
