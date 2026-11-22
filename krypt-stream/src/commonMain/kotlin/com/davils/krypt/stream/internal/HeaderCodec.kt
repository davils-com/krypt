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

import com.davils.krypt.core.io.ByteSource
import com.davils.krypt.core.io.readFully
import com.davils.krypt.stream.StreamFailure
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.StreamSuite
import com.davils.krypt.stream.internal.StreamRefusal.Companion.ensure
import com.davils.krypt.stream.internal.StreamRefusal.Companion.refuse
import kotlinx.io.bytestring.ByteString

internal object HeaderCodec {
    const val VERSION: Int = 1
    const val SALT_BYTES: Int = 32
    const val PREFIX_BYTES: Int = 7
    const val COMMITMENT_BYTES: Int = 32
    const val MAC_BYTES: Int = 32
    const val MINIMUM_SEGMENT: Int = 4_096
    const val MAXIMUM_SEGMENT: Int = 8_388_608
    const val MAXIMUM_LABEL: Int = 1_024
    const val MAXIMUM_WRAPPED: Int = 8_192

    private val MAGIC: ByteString = Octets.utf8("KRYPT")
    private const val CORE_BYTES: Int = 5 + 1 + 1 + 4 + SALT_BYTES + PREFIX_BYTES
    private const val SEGMENT_OFFSET: Int = 7
    private const val SALT_OFFSET: Int = 11
    private const val U16: Int = 2
    private const val U32: Int = 4
    private const val BYTE_MASK: Int = 0xFF

    fun core(suite: StreamSuite, segmentSize: Int, salt: ByteString, prefix: ByteString): ByteString = Octets.concat(
        MAGIC,
        ByteString(VERSION.toByte(), suite.id.toByte()),
        Octets.u32(segmentSize.toLong()),
        salt,
        prefix,
    )

    suspend fun read(source: ByteSource, limits: StreamLimits): Header {
        val core = exactly(source, CORE_BYTES)
        ensure(ByteString(data = core, startIndex = 0, endIndex = MAGIC.size) == MAGIC, StreamFailure.Malformed)
        ensure(core[MAGIC.size].toInt() == VERSION, StreamFailure.Unsupported)
        val suite = StreamSuite.entries.firstOrNull { entry -> entry.id == core[MAGIC.size + 1].toInt() }
            ?: refuse(StreamFailure.Unsupported)
        val segmentSize = Octets.unsigned(bytes = core, offset = SEGMENT_OFFSET, count = U32)
        ensure(segmentSize in MINIMUM_SEGMENT..MAXIMUM_SEGMENT, StreamFailure.Malformed)
        val count = exactly(source, 1)[0].toInt() and BYTE_MASK
        ensure(count in 1..limits.maximumRecipients, StreamFailure.Malformed)
        val recipients = List(count) { readRecipient(source) }
        return Header(
            suite = suite,
            segmentSize = segmentSize.toInt(),
            salt = ByteString(data = core, startIndex = SALT_OFFSET, endIndex = SALT_OFFSET + SALT_BYTES),
            noncePrefix = ByteString(data = core, startIndex = SALT_OFFSET + SALT_BYTES, endIndex = CORE_BYTES),
            recipients = recipients,
            commitment = ByteString(exactly(source, COMMITMENT_BYTES)),
            mac = ByteString(exactly(source, MAC_BYTES)),
        )
    }

    private suspend fun readRecipient(source: ByteSource): RecipientEntry {
        val kind = exactly(source, 1)[0].toInt() and BYTE_MASK
        val label = ByteString(exactly(source, length(source, MAXIMUM_LABEL)))
        val wrapped = ByteString(exactly(source, length(source, MAXIMUM_WRAPPED)))
        return RecipientEntry(kind = kind, label = label, wrapped = wrapped)
    }

    private suspend fun length(source: ByteSource, maximum: Int): Int {
        val length = Octets.unsigned(bytes = exactly(source, U16), offset = 0, count = U16).toInt()
        ensure(length <= maximum, StreamFailure.Malformed)
        return length
    }

    private suspend fun exactly(source: ByteSource, count: Int): ByteArray {
        val bytes = ByteArray(count)
        val read = source.readFully(bytes)
        ensure(read == count, StreamFailure.Malformed)
        return bytes
    }
}
