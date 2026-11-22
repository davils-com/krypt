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

package com.davils.krypt.stream.internal

import com.davils.krypt.stream.StreamSuite
import kotlinx.io.bytestring.ByteString

internal data class Header(
    val suite: StreamSuite,
    val segmentSize: Int,
    val salt: ByteString,
    val noncePrefix: ByteString,
    val recipients: List<RecipientEntry>,
    val commitment: ByteString,
    val mac: ByteString,
) {
    val core: ByteString
        get() = HeaderCodec.core(suite = suite, segmentSize = segmentSize, salt = salt, prefix = noncePrefix)

    val authenticated: ByteString
        get() {
            val entries = recipients.map { entry -> entry.encoded }
            return Octets.join(listOf(core, ByteString(recipients.size.toByte())) + entries + commitment)
        }

    val encoded: ByteString get() = Octets.concat(authenticated, mac)
}
