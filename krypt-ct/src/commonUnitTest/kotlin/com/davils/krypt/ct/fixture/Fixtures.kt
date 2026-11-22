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

package com.davils.krypt.ct.fixture

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.ct.Transparency
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val BYTE_BITS: Int = 8
private const val X509_ENTRY: Long = 0L
private const val PRECERT_ENTRY: Long = 1L

internal const val HOST: String = "example.com"
internal const val FIRST_OPERATOR: String = "First"
internal const val SECOND_OPERATOR: String = "Second"
internal const val SHORT_DAYS: Int = 90
internal const val LONG_DAYS: Int = 365
internal const val U16: Int = 2
internal const val U24: Int = 3
internal const val U64: Int = 8

internal val NOW: Instant = Instant.fromEpochSeconds(1_800_000_000L)

internal val crypto: Crypto = Crypto()

internal val signing: Crypto = Crypto(environment { policy = CryptoPolicy.Compatible })

internal val certificates: Certificates = Certificates(crypto)

internal val transparency: Transparency = Transparency(crypto)

internal fun der(block: DerWriter.() -> Unit): ByteString = Der.encode(block)

internal fun utf8(text: String): ByteString = ByteString(text.encodeToByteArray())

internal fun bytes(vararg values: Int): ByteString = ByteString(
    ByteArray(values.size) { index -> values[index].toByte() },
)

internal fun number(value: Long, count: Int): ByteString =
    ByteString(ByteArray(count) { index -> (value shr (count - 1 - index) * BYTE_BITS).toByte() })

internal fun concat(vararg parts: ByteString): ByteString =
    ByteString(parts.fold(ByteArray(0)) { all, part -> all + part.toByteArray() })

internal fun flipped(bytes: ByteString, index: Int): ByteString {
    val array = bytes.toByteArray()
    array[index] = (array[index].toInt() xor 1).toByte()
    return ByteString(array)
}

internal fun x509Entry(certificate: Certificate): ByteString = concat(
    number(X509_ENTRY, U16),
    number(certificate.encoded.size.toLong(), U24),
    certificate.encoded,
)

internal suspend fun precertEntry(issuer: Certificate, tbs: ByteString): ByteString = concat(
    number(PRECERT_ENTRY, U16),
    crypto.digests.digest(issuer.subjectPublicKeyInfo),
    number(tbs.size.toLong(), U24),
    tbs,
)
