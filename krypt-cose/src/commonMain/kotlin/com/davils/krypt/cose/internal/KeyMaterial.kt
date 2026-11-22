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

package com.davils.krypt.cose.internal

import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.cose.key.CoseCurve
import kotlinx.io.bytestring.ByteString

internal object KeyMaterial {
    private const val UNCOMPRESSED: Byte = 4
    private const val EC_VERSION: Long = 1
    private const val ONE_ASYMMETRIC_KEY: Long = 1
    private const val PUBLIC_KEY_TAG: Int = 1
    private const val RSA_PUBLIC_PARTS: Int = 2
    private const val RSA_PRIVATE_PARTS: Int = 8
    private val EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier.of("1.2.840.10045.2.1")
    private val RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.1")
    private val EDWARDS_OR_MONTGOMERY: Map<CoseCurve, ObjectIdentifier> = mapOf(
        CoseCurve.X25519 to ObjectIdentifier.of("1.3.101.110"),
        CoseCurve.X448 to ObjectIdentifier.of("1.3.101.111"),
        CoseCurve.Ed25519 to ObjectIdentifier.of("1.3.101.112"),
        CoseCurve.Ed448 to ObjectIdentifier.of("1.3.101.113"),
    )

    fun point(coordinates: List<ByteString>): ByteString =
        Bytes.concat(ByteString(UNCOMPRESSED), coordinates[0], coordinates[1])

    fun ecSpki(curve: CoseCurve, point: ByteString): ByteString = Der.encode {
        sequence {
            ecAlgorithm(curve)
            bitString(BitString(point))
        }
    }

    fun okpSpki(curve: CoseCurve, x: ByteString): ByteString = Der.encode {
        sequence {
            okpAlgorithm(curve)
            bitString(BitString(x))
        }
    }

    fun rsaSpki(modulus: ByteString, exponent: ByteString): ByteString = Der.encode {
        sequence {
            rsaAlgorithm()
            bitString(BitString(Der.encode { integers(listOf(modulus, exponent)) }))
        }
    }

    fun ecPkcs8(curve: CoseCurve, d: ByteString, point: ByteString?): SecretBytes {
        val inner = Der.encode {
            sequence {
                integer(EC_VERSION)
                octetString(d)
                point?.let { found -> explicit(PUBLIC_KEY_TAG) { bitString(BitString(found)) } }
            }
        }
        return pkcs8(version = 0L, inner = inner) { ecAlgorithm(curve) }
    }

    fun okpPkcs8(curve: CoseCurve, d: ByteString, x: ByteString?): SecretBytes {
        val inner = Der.encode { octetString(d) }
        val version = listOf(0L, ONE_ASYMMETRIC_KEY)[(x != null).compareTo(false)]
        return pkcs8(version = version, inner = inner, publicKey = x) { okpAlgorithm(curve) }
    }

    fun rsaPkcs8(parts: List<ByteString>): SecretBytes {
        val inner = Der.encode {
            sequence {
                integer(0L)
                parts.forEach { part -> integer(DerInteger.ofMagnitude(part)) }
            }
        }
        return pkcs8(version = 0L, inner = inner) { rsaAlgorithm() }
    }

    fun publicBits(spki: ByteString): ByteString {
        val bits = Der.decodeOrNull(spki) {
            readSequence {
                readElement(Tag.Sequence)
                readBitString().bytes
            }
        }
        return bits.sure()
    }

    fun ecCoordinates(spki: ByteString, size: Int): Pair<ByteString, ByteString> {
        val point = publicBits(spki)
        val x = point.substring(startIndex = 1, endIndex = 1 + size)
        return x to point.substring(startIndex = 1 + size, endIndex = point.size)
    }

    fun rsaPublic(spki: ByteString): List<ByteString> {
        val parts = Der.decodeOrNull(publicBits(spki)) {
            readSequence { readIntegers(RSA_PUBLIC_PARTS) }
        }
        return parts.sure()
    }

    fun privateValue(pkcs8: ByteString): ByteString {
        val inner = Der.decodeOrNull(pkcs8) {
            readSequence {
                readInteger()
                readElement(Tag.Sequence)
                val value = readOctetString()
                readRemaining()
                value
            }
        }
        return inner.sure()
    }

    fun ecPrivate(inner: ByteString): ByteString {
        val d = Der.decodeOrNull(inner) {
            readSequence {
                readInteger()
                val value = readOctetString()
                readRemaining()
                value
            }
        }
        return d.sure()
    }

    fun okpPrivate(inner: ByteString): ByteString = Der.decodeOrNull(inner) { readOctetString() }.sure()

    fun rsaPrivate(inner: ByteString): List<ByteString> {
        val parts = Der.decodeOrNull(inner) {
            readSequence {
                readInteger()
                val values = readIntegers(RSA_PRIVATE_PARTS)
                readRemaining()
                values
            }
        }
        return parts.sure()
    }

    private fun DerReader.readIntegers(count: Int): List<ByteString> = List(count) { readInteger().magnitude() }

    private fun DerWriter.integers(values: List<ByteString>) {
        sequence { values.forEach { value -> integer(DerInteger.ofMagnitude(value)) } }
    }

    private fun DerWriter.ecAlgorithm(curve: CoseCurve) {
        sequence {
            objectIdentifier(EC_PUBLIC_KEY)
            objectIdentifier(ObjectIdentifier.of(curve.curve.sure().objectIdentifier))
        }
    }

    private fun DerWriter.okpAlgorithm(curve: CoseCurve) {
        sequence { objectIdentifier(EDWARDS_OR_MONTGOMERY.getValue(curve)) }
    }

    private fun DerWriter.rsaAlgorithm() {
        sequence {
            objectIdentifier(RSA_ENCRYPTION)
            nullValue()
        }
    }

    private fun pkcs8(
        version: Long,
        inner: ByteString,
        publicKey: ByteString? = null,
        algorithm: DerWriter.() -> Unit,
    ): SecretBytes {
        val encoded = Der.encode {
            sequence {
                integer(version)
                algorithm()
                octetString(inner)
                publicKey?.let { bits ->
                    element(
                        tag = Tag.context(number = PUBLIC_KEY_TAG, isConstructed = false),
                        content = Bytes.concat(ByteString(0), bits),
                    )
                }
            }
        }
        return SecretBytes.copyOf(encoded)
    }
}
