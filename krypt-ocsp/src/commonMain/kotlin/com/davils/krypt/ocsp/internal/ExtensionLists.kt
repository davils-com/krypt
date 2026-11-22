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

package com.davils.krypt.ocsp.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.x509.extension.Extension
import kotlinx.io.bytestring.ByteString

internal const val MINIMUM_NONCE_BYTES: Int = 32
internal const val MAXIMUM_NONCE_BYTES: Int = 128

internal object ExtensionLists {
    val NONCE_ONLY: Set<ObjectIdentifier> = setOf(OcspOids.NONCE)

    fun DerReader.readExtensions(maximum: Int, understood: Set<ObjectIdentifier>): List<Extension> {
        val extensions = readListOf(maximum) {
            readSequence {
                val id = readObjectIdentifier()
                val isCritical = isNext(Tag.Boolean)
                if (isCritical && !readBoolean()) refuse(DerFailure.InvalidValue, "a critical flag that is true")
                Extension(id = id, isCritical = isCritical, value = readOctetString())
            }
        }
        val ids = extensions.map { extension -> extension.id }
        val isUnderstood = extensions.all { extension -> !extension.isCritical || extension.id in understood }
        val isDistinct = ids.toSet().size == ids.size
        if (extensions.isEmpty() || !isDistinct || !isUnderstood) {
            refuse(DerFailure.InvalidValue, "distinct extensions that are understood")
        }
        return extensions
    }

    fun DerReader.nonceOf(extensions: List<Extension>): ByteString? {
        val extension = extensions.firstOrNull { found -> found.id == OcspOids.NONCE } ?: return null
        val nonce = Der.decodeOrNull(extension.value) { readOctetString() }
        val valid = nonce?.takeIf { found -> found.size in 1..MAXIMUM_NONCE_BYTES }
        return valid ?: refuse(DerFailure.InvalidValue, "a nonce of 1 to $MAXIMUM_NONCE_BYTES bytes")
    }

    fun nonceExtension(nonce: ByteString): Extension =
        Extension(id = OcspOids.NONCE, isCritical = false, value = Der.encode { octetString(nonce) })

    fun DerWriter.writeExtensions(extensions: List<Extension>) {
        sequence {
            extensions.forEach { extension ->
                sequence {
                    objectIdentifier(extension.id)
                    if (extension.isCritical) boolean(true)
                    octetString(extension.value)
                }
            }
        }
    }
}
