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

package com.davils.krypt.storage.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.asn1.readText
import com.davils.krypt.storage.blob.ObjectMetadata
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val VERSION: Int = 1
private const val MAXIMUM_ATTRIBUTES: Int = 32

internal object MetadataCodec {
    fun encode(metadata: ObjectMetadata): ByteString = Der.encode {
        sequence {
            integer(VERSION.toLong())
            utf8String(metadata.name)
            integer(metadata.version)
            utf8String(metadata.contentType)
            integer(metadata.createdAt.toEpochMilliseconds())
            sequence {
                metadata.attributes.forEach { (key, value) ->
                    sequence {
                        utf8String(key)
                        utf8String(value)
                    }
                }
            }
        }
    }

    fun decodeOrNull(encoded: ByteString): ObjectMetadata? = Der.decodeOrNull(encoded) {
        readSequence {
            readInt(VERSION..VERSION)
            val name = readText(Tag.Utf8String)
            val version = readLong()
            val contentType = readText(Tag.Utf8String)
            val createdAt = Instant.fromEpochMilliseconds(readLong())
            val attributes = readListOf(
                MAXIMUM_ATTRIBUTES,
            ) { readSequence { readText(Tag.Utf8String) to readText(Tag.Utf8String) } }
            ObjectMetadata(
                name = name,
                version = version,
                contentType = contentType,
                createdAt = createdAt,
                attributes = attributes.toMap(),
            )
        }
    }

    private fun DerReader.readLong(): Long = readInteger().toLongOrNull() ?: refuse(DerFailure.InvalidValue, "a number")
}
