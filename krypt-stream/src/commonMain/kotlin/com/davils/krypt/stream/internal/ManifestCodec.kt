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

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.asn1.readText
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.manifest.Manifest
import com.davils.krypt.stream.manifest.ManifestKind
import com.davils.krypt.stream.manifest.ManifestSignature
import com.davils.krypt.stream.manifest.SignedManifest
import kotlinx.io.bytestring.ByteString

private const val VERSION: Int = 1
private const val COUNTERSIGNS: Int = 0
private const val TIMESTAMP: Int = 1

internal object ManifestCodec {
    fun encode(manifest: Manifest): ByteString = Der.encode { writeManifest(manifest) }

    fun encodeSigned(signed: SignedManifest): ByteString = Der.encode {
        sequence {
            writeManifest(signed.manifest)
            sequence {
                signed.signatures.forEach { signature ->
                    sequence {
                        octetString(signature.signature)
                        signature.countersigns?.let { index -> explicit(COUNTERSIGNS) { integer(index.toLong()) } }
                        signature.timestamp?.let { token -> explicit(TIMESTAMP) { octetString(token) } }
                    }
                }
            }
        }
    }

    fun decodeSignedOrNull(encoded: ByteString, limits: StreamLimits): SignedManifest? = Der.decodeOrNull(encoded) {
        readSequence {
            val manifest = readManifest(limits)
            val signatures = readListOf(limits.maximumSignatures) { readSignature() }
            val isOrdered = signatures.withIndex().all { (index, signature) -> (signature.countersigns ?: -1) < index }
            if (!isOrdered || signatures.isEmpty()) {
                refuse(
                    DerFailure.InvalidValue,
                    "countersignatures of earlier signatures",
                )
            }
            SignedManifest(manifest, signatures)
        }
    }

    private fun DerWriter.writeManifest(manifest: Manifest) {
        sequence {
            integer(VERSION.toLong())
            integer(manifest.kind.ordinal.toLong())
            utf8String(manifest.digest.name)
            integer(manifest.segmentSize.toLong())
            integer(manifest.length)
            integer(manifest.segments)
            octetString(manifest.root)
            octetString(manifest.context)
        }
    }

    private fun DerReader.readManifest(limits: StreamLimits): Manifest = readSequence {
        readInt(VERSION..VERSION)
        val kind = ManifestKind.entries[readInt(ManifestKind.entries.indices)]
        val name = readText(Tag.Utf8String)
        val digest = Manifest.DIGESTS.firstOrNull { entry -> entry.name == name } ?: refuse(
            DerFailure.InvalidValue,
            "a digest",
        )
        val segmentSize = readInt(HeaderCodec.MINIMUM_SEGMENT..HeaderCodec.MAXIMUM_SEGMENT)
        val length = readLong(0L..Long.MAX_VALUE, "a length")
        val segments = readLong(0L..limits.maximumSegments, "a number of segments")
        val root = readOctetString()
        if (root.size != digest.outputBytes) refuse(DerFailure.InvalidValue, "a root of the digest")
        Manifest(
            kind = kind,
            digest = digest,
            segmentSize = segmentSize,
            length = length,
            segments = segments,
            root = root,
            context = readOctetString(),
        )
    }

    private fun DerReader.readLong(range: LongRange, detail: String): Long {
        val value = readInteger().toLongOrNull()
        return value?.takeIf { found -> found in range } ?: refuse(DerFailure.InvalidValue, detail)
    }

    private fun DerReader.readSignature(): ManifestSignature = readSequence {
        ManifestSignature(
            signature = readOctetString(),
            countersigns = readOptionalExplicit(COUNTERSIGNS) { readInt(0..Int.MAX_VALUE) },
            timestamp = readOptionalExplicit(TIMESTAMP) { readOctetString() },
        )
    }
}
