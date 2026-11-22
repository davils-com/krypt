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
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.AcmeRequest
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.StrictJson
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsMessage
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

internal class FakeRequests(private val state: FakeState) {
    suspend fun verify(request: AcmeRequest): SignedRequest {
        val message = messageOf(request.body)
        val header = message.signatures.single().protectedHeader
        refuseUnless(condition = header.textOf(URL) == request.url, type = AcmeProblemType.Unauthorized)
        state.useNonce(header.textOf(NONCE))
        val jwk = header.objectOf(JWK)
        val kid = header.textOf(KEY_ID)
        val hasJwk = jwk != null
        val hasKeyId = kid != null
        refuseUnless(hasJwk != hasKeyId)
        val account = kid?.let { found -> accountAt(found) }
        val key = keyOf(account = account, jwk = jwk)
        val payload = verified(message = message, key = JoseKey.Public(key), algorithms = SIGNING)
        return SignedRequest(url = request.url, payload = payload, key = key, jwk = jwk, account = account)
    }

    suspend fun verifyInner(
        body: JsonValue.Object,
        url: String,
        key: JoseKey,
        algorithms: Set<JwsAlgorithm>,
    ): JsonValue.Object {
        val message = messageOf(body.encode().encodeToByteString())
        val header = message.signatures.single().protectedHeader
        refuseUnless(condition = header.textOf(URL) == url && NONCE !in header, type = AcmeProblemType.Unauthorized)
        return present(verified(message = message, key = key, algorithms = algorithms))
    }

    fun headerOf(body: JsonValue.Object): JsonValue.Object {
        val message = messageOf(body.encode().encodeToByteString())
        return message.signatures.single().protectedHeader
    }

    fun publicKeyOf(jwk: JsonValue.Object): PublicKey {
        val decoded = state.keys.decode(jwk.encode())
        val key = decoded.flatMap { found -> state.keys.publicKey(found) }
        return present(value = key.getOrNull(), type = AcmeProblemType.BadPublicKey)
    }

    private suspend fun verified(message: JwsMessage, key: JoseKey, algorithms: Set<JwsAlgorithm>): JsonValue.Object? {
        val verification = state.jws.verify(message = message, keys = listOf(key), algorithms = algorithms)
        val verified = present(value = verification.getOrNull(), type = AcmeProblemType.Unauthorized)
        return verified.payload.takeIf { payload -> payload.size > 0 }?.let { payload -> objectOf(payload) }
    }

    private fun keyOf(account: FakeAccount?, jwk: JsonValue.Object?): PublicKey = when (account) {
        null -> publicKeyOf(present(jwk))
        is FakeAccount -> account.key
    }

    private fun accountAt(url: String): FakeAccount {
        val account = state.accounts.values.firstOrNull { found -> found.url == url }
        val existing = present(value = account, type = AcmeProblemType.AccountDoesNotExist)
        refuseUnless(condition = existing.status == VALID, type = AcmeProblemType.Unauthorized)
        return existing
    }

    private fun messageOf(body: ByteString): JwsMessage {
        val text = body.toByteArray().decodeToString()
        val message = present(state.jws.decode(text).getOrNull())
        refuseUnless(!message.isCompact && message.signatures.size == 1)
        return message
    }

    private fun objectOf(bytes: ByteString): JsonValue.Object = present(StrictJson.decodeObject(bytes).getOrNull())

    companion object {
        const val URL: String = "url"
        const val NONCE: String = "nonce"
        const val JWK: String = "jwk"
        const val KEY_ID: String = "kid"
        const val VALID: String = "valid"
        val MAC: Set<JwsAlgorithm> = setOf(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512)
        val SIGNING: Set<JwsAlgorithm> = JwsAlgorithm.entries.toSet() - MAC
    }
}
