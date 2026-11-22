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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.testing.acme

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.acme.AcmeClient
import com.davils.krypt.acme.AcmeFailure
import com.davils.krypt.acme.AcmeMethod
import com.davils.krypt.acme.AcmeProblem
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.AcmeRequest
import com.davils.krypt.acme.AcmeResponse
import com.davils.krypt.acme.account.AccountKey
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.core.encoding.Base64Alphabet
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.StrictJson
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsSigner
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.testing.testCrypto
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

internal const val BASE: String = FakeAcmeServer.DEFAULT_BASE_URL
internal const val OK: String = "ok"
internal const val KID: String = "kid"
internal const val JWK: String = "jwk"
internal const val URL: String = "url"
internal const val NONCE: String = "nonce"
private const val MAC_BYTES: Int = 32
private const val ERROR_PREFIX: String = "urn:ietf:params:acme:error:"

internal val crypto: Crypto = testCrypto()
internal val jws: Jws = Jws(crypto)
private val keys = JsonWebKeys(crypto)

internal suspend fun key(): AccountKey = AccountKey(crypto.keys.generate(KeyType.P256).privateKey)

internal fun clientOf(server: FakeAcmeServer): AcmeClient =
    AcmeClient(transport = server, directoryUrl = server.directoryUrl, crypto = crypto)

internal fun Outcome<*, AcmeFailure>.problem(): AcmeProblemType? = (failureOrNull() as? AcmeProblem)?.kind

internal fun <T> Outcome<T, AcmeFailure>.value(): T = checkNotNull(getOrNull()) { "Expected a success: $this" }

internal fun jwkOf(key: AccountKey): JsonValue.Object {
    val encoded = keys.of(key.publicKey).encode()
    return checkNotNull(StrictJson.decodeObject(encoded.encodeToByteString()).getOrNull())
}

internal fun base64(bytes: ByteString): String =
    Base64.encode(bytes = bytes, alphabet = Base64Alphabet.Url, padding = false)

internal fun macKey(seed: Int): SecretKey =
    SecretKey.of(SecretBytes.copyOf(ByteArray(MAC_BYTES) { index -> (index + seed).toByte() }))

internal fun jsonText(value: String): JsonValue.Text = JsonValue.Text(value)

internal fun AcmeResponse.code(): String {
    val json = StrictJson.decodeObject(body).getOrNull()
    val type = (json?.get("type") as? JsonValue.Text)?.value
    return type?.removePrefix(ERROR_PREFIX) ?: OK
}

internal class RawRequests(private val server: FakeAcmeServer) {
    suspend fun nonce(): String {
        val response = server.exchange(AcmeRequest(method = AcmeMethod.Head, url = "$BASE/new-nonce"))
        return response.headers("Replay-Nonce").single()
    }

    suspend fun send(url: String, body: String, method: AcmeMethod = AcmeMethod.Post): String {
        val response = server.exchange(AcmeRequest(method = method, url = url, body = body.encodeToByteString()))
        return response.code()
    }

    suspend fun signed(
        payload: String,
        key: AccountKey,
        header: List<Pair<String, JsonValue>>,
        signer: JoseKey = JoseKey.Private(key.privateKey),
        algorithm: JwsAlgorithm = key.algorithm,
    ): String {
        val jwsSigner = JwsSigner(key = signer, algorithm = algorithm, header = JsonValue.Object(header))
        return jws.signJson(payload = payload.encodeToByteString(), signers = listOf(jwsSigner), isFlattened = true)
    }

    suspend fun post(
        url: String,
        key: AccountKey,
        payload: String = "",
        kid: String? = null,
        extra: List<Pair<String, JsonValue>> = emptyList(),
        hasNonce: Boolean = true,
        headerUrl: String = url,
    ): String {
        val identity = kid?.let { found -> KID to jsonText(found) } ?: (JWK to jwkOf(key))
        val nonce = (NONCE to jsonText(nonce())).takeIf { hasNonce }
        val header = listOfNotNull(identity, nonce, URL to jsonText(headerUrl)) + extra
        return send(url = url, body = signed(payload = payload, key = key, header = header))
    }
}
