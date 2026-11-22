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

package com.davils.krypt.cose.fixture

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.core.environment
import com.davils.krypt.cose.Cose
import com.davils.krypt.cose.cbor.CborMode
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeys
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Instant

internal const val CONTENT: String = "This is the content."

internal val NOW: Instant = Instant.fromEpochSeconds(1_444_064_944L)

internal val crypto: Crypto = Crypto(environment { clock = FixedClock })

internal val cose: Cose = Cose(crypto)

internal val relaxed: Cose = Cose(crypto = crypto, mode = CborMode.Relaxed)

internal val coseKeys: CoseKeys = CoseKeys(crypto)

internal fun hex(text: String): ByteString = checkNotNull(Hex.decode(text.lowercase()).getOrNull())

internal fun hexOf(bytes: ByteString): String = Hex.encode(bytes).uppercase()

internal fun utf8(text: String): ByteString = text.encodeToByteString()

internal fun key(encoded: String): CoseKey = checkNotNull(coseKeys.decode(hex(encoded)).getOrNull())

internal fun replaying(bytes: String): Crypto = Crypto(
    environment {
        clock = FixedClock
        random = Replayed(hex(bytes).toByteArray())
    },
)

internal fun <T> Outcome<T, *>.value(): T = checkNotNull(getOrNull())

internal fun Outcome<*, *>.failure(): Any? = failureOrNull()

internal fun withoutKeyId(key: CoseKey): CoseKey = CoseKey(
    type = key.type,
    curve = key.curve,
    keyId = null,
    algorithm = key.algorithm,
    operations = key.operations,
    baseIv = key.baseIv,
    publicKey = key.publicKey,
    privateKey = key.privateKey,
    secretKey = key.secretKey,
)
