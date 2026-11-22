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

package com.davils.krypt.x509.fixture

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.crl.RevocationLists
import com.davils.krypt.x509.request.CertificationRequests
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal const val ROOT: String = "Root"
internal const val DAYS: Int = 30

internal val NOW: Instant = Instant.fromEpochSeconds(1_800_000_000L)

internal val crypto: Crypto = Crypto()

internal val certificates: Certificates = Certificates(crypto)

internal val requests: CertificationRequests = CertificationRequests(crypto)

internal val revocationLists: RevocationLists = RevocationLists(crypto)

internal fun der(block: DerWriter.() -> Unit): ByteString = Der.encode(block)

internal fun utf8(text: String): ByteString = ByteString(text.encodeToByteArray())

internal fun flipped(bytes: ByteString, index: Int): ByteString {
    val array = bytes.toByteArray()
    array[index] = (array[index].toInt() xor 1).toByte()
    return ByteString(array)
}
