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

package com.davils.krypt.jose.internal

import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.jose.jwk.Jwk
import com.davils.krypt.jose.jwk.JwkCurve
import com.davils.krypt.jose.jwk.JwkType
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

private const val UNCOMPRESSED: Byte = 4
private const val EC_VERSION: Long = 1L
private const val PUBLIC_KEY_TAG: Int = 1
private const val RSA_PRIVATE_OFFSET: Int = 3

internal object KeyDer {
    private val EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier.of("1.2.840.10045.2.1")
    private val RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.1.1")
    private val OCTET_KEYS: Map<JwkCurve, ObjectIdentifier> = mapOf(
        JwkCurve.X25519 to ObjectIdentifier.of("1.3.101.110"),
        JwkCurve.X448 to ObjectIdentifier.of("1.3.101.111"),
        JwkCurve.Ed25519 to ObjectIdentifier.of("1.3.101.112"),
        JwkCurve.Ed448 to ObjectIdentifier.of("1.3.101.113"),
    )
    private val ALGORITHMS: Map<JwkType, DerWriter.(Jwk) -> Unit> = mapOf(
        JwkType.Ec to { jwk -> ecAlgorithm(jwk) },
        JwkType.Okp to { jwk -> okpAlgorithm(jwk) },
        JwkType.Rsa to { _ -> rsaAlgorithm() },
    )
    private val PUBLIC_BITS: Map<JwkType, (Jwk) -> ByteString> = mapOf(
        JwkType.Ec to { jwk -> pointBytes(jwk) },
        JwkType.Okp to { jwk -> parameterOf(jwk, JwkNames.X) },
        JwkType.Rsa to { jwk -> rsaPublicKey(jwk) },
    )
    private val PRIVATE_KEYS: Map<JwkType, (Jwk) -> ByteString> = mapOf(
        JwkType.Ec to { jwk -> ecPrivateKey(jwk) },
        JwkType.Okp to { jwk -> Der.encode { octetString(secretOf(jwk, JwkNames.D)) } },
        JwkType.Rsa to { jwk -> rsaPrivateKey(jwk) },
    )
    private val PUBLIC_PARAMETERS: Map<JwkType, (ByteString, Int) -> List<Pair<String, ByteString>>> = mapOf(
        JwkType.Ec to { bytes, size -> pointOf(bytes = bytes, size = size) },
        JwkType.Okp to { bytes, _ -> listOf(JwkNames.X to bytes) },
        JwkType.Rsa to { bytes, _ -> rsaPublicOf(bytes) },
    )
    private val PRIVATE_PARAMETERS: Map<JwkType, (ByteString, Int) -> List<Pair<String, SecretBytes>>> = mapOf(
        JwkType.Ec to { der, size -> ecPrivateOf(der = der, size = size) },
        JwkType.Okp to { der, _ -> okpPrivateOf(der) },
        JwkType.Rsa to { der, _ -> rsaPrivateOf(der) },
    )

    fun spki(jwk: Jwk): ByteString = Der.encode {
        sequence {
            raw(algorithmOf(jwk))
            bitString(BitString(publicBitsOf(jwk)))
        }
    }

    fun pkcs8(jwk: Jwk): SecretBytes {
        val encoded = Der.encode {
            sequence {
                integer(0L)
                raw(algorithmOf(jwk))
                octetString(privateKeyOf(jwk))
            }
        }
        return SecretBytes.copyOf(encoded)
    }

    fun publicParameters(type: JwkType, size: Int, key: PublicKey): List<Pair<String, ByteString>> {
        val bits = der(key.encoded) { readSequence { readElement() to readBitString() } }
        val bytes = bits.second.bytes
        return PUBLIC_PARAMETERS.getValue(type)(bytes, size)
    }

    fun privateParameters(type: JwkType, size: Int, pkcs8: SecretBytes): List<Pair<String, SecretBytes>> {
        val inner = pkcs8.reveal { bytes -> der(ByteString(bytes)) { readInnerKey() } }
        return PRIVATE_PARAMETERS.getValue(type)(inner, size)
    }

    private fun okpPrivateOf(der: ByteString): List<Pair<String, SecretBytes>> {
        val key = der(der) { readOctetString() }
        return listOf(JwkNames.D to SecretBytes.copyOf(key))
    }

    private fun DerReader.readInnerKey(): ByteString = readSequence {
        readInteger()
        readElement()
        val key = readOctetString()
        readRemaining()
        key
    }

    private fun algorithmOf(jwk: Jwk): ByteString = Der.encode {
        sequence { ALGORITHMS.getValue(jwk.type)(this, jwk) }
    }

    private fun DerWriter.ecAlgorithm(jwk: Jwk) {
        val curve = invariant(jwk.curve?.ellipticCurve)
        objectIdentifier(EC_PUBLIC_KEY)
        objectIdentifier(ObjectIdentifier.of(curve.objectIdentifier))
    }

    private fun DerWriter.okpAlgorithm(jwk: Jwk) {
        objectIdentifier(OCTET_KEYS.getValue(invariant(jwk.curve)))
    }

    private fun DerWriter.rsaAlgorithm() {
        objectIdentifier(RSA_ENCRYPTION)
        nullValue()
    }

    private fun publicBitsOf(jwk: Jwk): ByteString = PUBLIC_BITS.getValue(jwk.type)(jwk)

    private fun privateKeyOf(jwk: Jwk): ByteString = PRIVATE_KEYS.getValue(jwk.type)(jwk)

    private fun <T> der(bytes: ByteString, block: DerReader.() -> T): T =
        invariant(Der.decodeOrNull(bytes, block = block))

    private fun rsaPublicKey(jwk: Jwk): ByteString = Der.encode {
        sequence {
            integer(DerInteger.ofMagnitude(parameterOf(jwk, JwkNames.N)))
            integer(DerInteger.ofMagnitude(parameterOf(jwk, JwkNames.E)))
        }
    }

    private fun ecPrivateKey(jwk: Jwk): ByteString = Der.encode {
        sequence {
            integer(EC_VERSION)
            octetString(secretOf(jwk, JwkNames.D))
            explicit(PUBLIC_KEY_TAG) { bitString(BitString(pointBytes(jwk))) }
        }
    }

    private fun rsaPrivateKey(jwk: Jwk): ByteString = Der.encode {
        sequence {
            integer(0L)
            integer(DerInteger.ofMagnitude(parameterOf(jwk, JwkNames.N)))
            integer(DerInteger.ofMagnitude(parameterOf(jwk, JwkNames.E)))
            JwkNames.RSA_PRIVATE.forEach { name -> integer(DerInteger.ofMagnitude(secretOf(jwk, name))) }
        }
    }

    private fun pointBytes(jwk: Jwk): ByteString {
        val x = parameterOf(jwk, JwkNames.X).toByteArray()
        val y = parameterOf(jwk, JwkNames.Y).toByteArray()
        return ByteString(byteArrayOf(UNCOMPRESSED) + x + y)
    }

    private fun parameterOf(jwk: Jwk, name: String): ByteString = invariant(jwk.parameter(name))

    private fun secretOf(jwk: Jwk, name: String): ByteString =
        invariant(jwk.secret(name)).reveal { bytes -> ByteString(bytes) }

    private fun pointOf(bytes: ByteString, size: Int): List<Pair<String, ByteString>> {
        val point = bytes.toByteArray()
        check(point.size == 1 + 2 * size && point[0] == UNCOMPRESSED)
        return listOf(
            JwkNames.X to ByteString(data = point, startIndex = 1, endIndex = 1 + size),
            JwkNames.Y to ByteString(data = point, startIndex = 1 + size, endIndex = point.size),
        )
    }

    private fun rsaPublicOf(bytes: ByteString): List<Pair<String, ByteString>> {
        val integers = der(bytes) { readSequence { readInteger() to readInteger() } }
        return listOf(JwkNames.N to integers.first.magnitude(), JwkNames.E to integers.second.magnitude())
    }

    private fun ecPrivateOf(der: ByteString, size: Int): List<Pair<String, SecretBytes>> {
        val scalar = der(der) { readSequence { readEcScalar() } }
        val bytes = scalar.toByteArray()
        val padded = ByteArray(size)
        bytes.copyInto(destination = padded, destinationOffset = size - bytes.size)
        bytes.fill(0)
        return listOf(JwkNames.D to SecretBytes.adopt(padded))
    }

    private fun DerReader.readEcScalar(): ByteString {
        readInteger()
        val key = readOctetString()
        readRemaining()
        return key
    }

    private fun rsaPrivateOf(der: ByteString): List<Pair<String, SecretBytes>> {
        val integers = der(der) { readSequence { readRemaining() } }
        val values = integers.drop(RSA_PRIVATE_OFFSET).map { element ->
            val integer = invariant(DerInteger.decodeOrNull(element.content))
            SecretBytes.copyOf(integer.magnitude())
        }
        return JwkNames.RSA_PRIVATE.zip(values)
    }
}
