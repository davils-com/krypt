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

package com.davils.krypt.jose.fixture

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.RandomSource
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.core.encoding.Base64Alphabet
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.jose.jwk.Jwk
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Instant

internal val NOW: Instant = Instant.fromEpochSeconds(1_800_000_000L)

internal val crypto: Crypto = Crypto(environment { clock = FixedClock })

internal val compatible: Crypto = Crypto(
    environment {
        clock = FixedClock
        policy = CryptoPolicy.Compatible
    },
)

internal val keys: JsonWebKeys = JsonWebKeys(crypto)

internal val compatibleKeys: JsonWebKeys = JsonWebKeys(compatible)

internal fun hex(text: String): ByteString = checkNotNull(Hex.decode(text).getOrNull())

internal fun utf8(text: String): ByteString = text.encodeToByteString()

internal fun base64(bytes: ByteString): String =
    Base64.encode(bytes = bytes, alphabet = Base64Alphabet.Url, padding = false)

internal fun base64(text: String): String = base64(utf8(text))

internal fun unbase64(text: String): ByteString =
    checkNotNull(Base64.decode(text = text, alphabet = Base64Alphabet.Url, padding = false).getOrNull())

internal fun jwkOf(text: String, engine: JsonWebKeys = keys): Jwk = checkNotNull(engine.decode(text).getOrNull())

internal suspend fun keyOf(text: String, engine: JsonWebKeys = compatibleKeys): JoseKey =
    checkNotNull(engine.key(jwkOf(text, engine)).getOrNull())

internal fun publicOf(text: String, engine: JsonWebKeys = compatibleKeys): JoseKey {
    val jwk = jwkOf(text, engine)
    val publicKey = checkNotNull(engine.publicKey(jwk).getOrNull())
    return JoseKey.Public(key = publicKey, keyId = jwk.keyId)
}

internal fun <T> Outcome<T, JoseFailure>.value(): T = checkNotNull(getOrNull()) { "Expected a success: $this" }

internal fun <T> Outcome<T, JoseFailure>.failure(): JoseFailure? = failureOrNull()

internal fun replayed(vararg chunks: ByteString): RandomSource {
    val queue = ArrayDeque(chunks.toList())
    return RandomSource { target ->
        val next = queue.removeFirst()
        check(next.size == target.size) { "The replayed chunk has ${next.size} bytes, not ${target.size}" }
        next.toByteArray().copyInto(target)
    }
}
