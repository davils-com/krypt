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

package com.davils.krypt.keyset.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readListOf
import com.davils.krypt.asn1.readText
import com.davils.krypt.keyset.Keyset
import com.davils.krypt.keyset.KeysetFailure
import com.davils.krypt.keyset.KeysetKey
import com.davils.krypt.keyset.KeysetLimits
import com.davils.krypt.keyset.internal.Purposes.readPurpose
import com.davils.krypt.keyset.internal.Purposes.writePurpose
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

private const val SECRET: Int = 0
private const val PRIVATE: Int = 1
private const val PUBLIC: Int = 2

internal object KeysetCodec {
    const val VERSION: Int = 1

    fun encode(crypto: Crypto, keyset: Keyset): ByteString = Der.encode {
        sequence {
            integer(VERSION.toLong())
            writePurpose(keyset.purpose)
            octetString(keyset.primaryId.bytes)
            sequence {
                keyset.keys.forEach { key -> writeKey(crypto, key) }
            }
        }
    }

    suspend fun decode(
        crypto: Crypto,
        encoded: ByteString,
        limits: KeysetLimits,
        isPublic: Boolean,
    ): Outcome<Keyset, KeysetFailure> {
        val isSmall = encoded.size <= limits.maximumEncodedBytes
        val raw = encoded.takeIf { isSmall }?.let { bytes ->
            Der.decodeOrNull(bytes) { readKeyset(limits.maximumKeys) }
        } ?: return Outcome.Failure(KeysetFailure.Malformed)
        return try {
            Outcome.Success(KeysetAssembly(crypto = crypto, isPublic = isPublic).assemble(raw))
        } catch (refusal: Refusal) {
            Outcome.Failure(refusal.failure)
        }
    }

    fun encodeEncrypted(keyUri: String, ciphertext: ByteString): ByteString = Der.encode {
        sequence {
            integer(VERSION.toLong())
            utf8String(keyUri)
            octetString(ciphertext)
        }
    }

    fun decodeEncryptedOrNull(encoded: ByteString, limits: KeysetLimits): Pair<String, ByteString>? {
        val isSmall = encoded.size <= limits.maximumEncodedBytes
        return encoded.takeIf { isSmall }?.let { bytes ->
            Der.decodeOrNull(bytes) {
                readSequence {
                    readInt(VERSION..VERSION)
                    readText(Tag.Utf8String) to readOctetString()
                }
            }
        }
    }

    private fun DerWriter.writeKey(crypto: Crypto, key: KeysetKey) {
        sequence {
            octetString(key.id.bytes)
            integer(key.status.ordinal.toLong())
            integer(key.createdAt.toEpochMilliseconds())
            key.secret?.let { secret ->
                explicit(
                    SECRET,
                ) { secret.export().use { owned -> owned.reveal { bytes -> octetString(ByteString(bytes)) } } }
            }
            key.privateKey?.let { private ->
                val encoded = crypto.keys.encodePrivate(private)
                explicit(PRIVATE) { encoded.use { owned -> owned.reveal { bytes -> octetString(ByteString(bytes)) } } }
            }
            key.publicKey?.let { public -> explicit(PUBLIC) { octetString(public.encoded) } }
        }
    }

    private fun DerReader.readKeyset(maximumKeys: Int): RawKeyset = readSequence {
        val version = readInt(1..Int.MAX_VALUE)
        val purpose = readPurpose()
        val primary = readOctetString()
        val keys = readListOf(maximumKeys) { readKey() }
        RawKeyset(version = version, purpose = purpose, primary = primary, keys = keys)
    }

    private fun DerReader.readKey(): RawKey = readSequence {
        RawKey(
            id = readOctetString(),
            status = readInt(0..Int.MAX_VALUE),
            createdAt = readInteger().toLongOrNull() ?: refuse(DerFailure.InvalidValue, "a time"),
            secret = readOptionalExplicit(SECRET) { readOctetString() },
            privateKey = readOptionalExplicit(PRIVATE) { readOctetString() },
            publicKey = readOptionalExplicit(PUBLIC) { readOctetString() },
        )
    }
}
