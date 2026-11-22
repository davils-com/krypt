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

package com.davils.krypt.ocsp.fixture

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.core.environment
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal const val ROOT: String = "Root"
internal const val LEAF: String = "leaf"
internal const val DAYS: Int = 30
internal const val SHA256_BYTES: Int = 32

internal val NOW: Instant = Instant.fromEpochSeconds(1_800_000_000L)

internal val crypto: Crypto = Crypto(environment { clock = FixedClock })

internal val certificates: Certificates = Certificates(crypto)

internal val ocsp: Ocsp = Ocsp(crypto)

internal fun der(block: DerWriter.() -> Unit): ByteString = Der.encode(block)

internal fun filled(size: Int): ByteString = ByteString(ByteArray(size))
