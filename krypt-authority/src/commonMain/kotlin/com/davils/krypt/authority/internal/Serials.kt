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

package com.davils.krypt.authority.internal

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

private const val SERIAL_BYTES: Int = 20
private const val POSITIVE_MASK: Int = 0x7F
private const val NONZERO_BIT: Int = 0x40

internal object Serials {
    fun next(crypto: Crypto): DerInteger {
        val bytes = crypto.environment.random.bytes(SERIAL_BYTES)
        bytes[0] = (bytes[0].toInt() and POSITIVE_MASK or NONZERO_BIT).toByte()
        return DerInteger.ofMagnitude(ByteString(bytes))
    }
}
