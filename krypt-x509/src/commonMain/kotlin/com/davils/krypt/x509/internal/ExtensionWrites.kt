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

package com.davils.krypt.x509.internal

import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.extension.AccessDescription
import com.davils.krypt.x509.extension.DistributionPoint
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.internal.NameCodec.writeGeneralName
import com.davils.krypt.x509.name.GeneralName
import kotlinx.io.bytestring.ByteString

internal object ExtensionWrites {
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

    fun names(names: List<GeneralName>): ByteString = Der.encode {
        sequence { names.forEach { name -> writeGeneralName(name) } }
    }

    fun DerWriter.writeImplicitNames(number: Int, names: List<GeneralName>) {
        constructed(
            Tag.context(number = number, isConstructed = true),
        ) { names.forEach { name -> writeGeneralName(name) } }
    }

    fun distributionPoints(points: List<DistributionPoint>): ByteString = Der.encode {
        sequence {
            points.forEach { point ->
                sequence {
                    if (point.names.isNotEmpty()) explicit(0) { writeImplicitNames(0, point.names) }
                    point.reasons?.let { reasons ->
                        bitString(
                            reasonBits(reasons),
                            Tag.context(number = 1, isConstructed = false),
                        )
                    }
                    if (point.crlIssuer.isNotEmpty()) writeImplicitNames(2, point.crlIssuer)
                }
            }
        }
    }

    fun accessDescriptions(descriptions: List<AccessDescription>): ByteString = Der.encode {
        sequence {
            descriptions.forEach { description ->
                sequence {
                    objectIdentifier(description.method)
                    writeGeneralName(description.location)
                }
            }
        }
    }

    fun objectIdentifiers(ids: List<ObjectIdentifier>): ByteString = Der.encode {
        sequence { ids.forEach { id -> objectIdentifier(id) } }
    }

    fun reasonBits(reasons: Set<RevocationReason>): BitString =
        BitString.ofNamedBits(reasons.mapNotNull { reason -> reason.bit }.toSet())
}
