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

package com.davils.krypt.testing.acme

import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.AcmeRequest
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.core.encoding.Base64Alphabet
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey

private const val NONCE_BYTES: Int = 16
private const val MAXIMUM_NONCES: Int = 1_024

internal class FakeState(
    val crypto: Crypto,
    val baseUrl: String,
    val externalAccounts: Map<String, SecretKey>,
    val processingPolls: Int,
) {
    val jws: Jws = Jws(crypto)
    val keys: JsonWebKeys = JsonWebKeys(crypto)
    val issuer: FakeIssuer = FakeIssuer(crypto)
    val accounts: MutableMap<Int, FakeAccount> = mutableMapOf()
    val orders: MutableMap<Int, FakeOrder> = mutableMapOf()
    val authorizations: MutableMap<Int, FakeAuthorization> = mutableMapOf()
    val challenges: MutableMap<Int, FakeChallenge> = mutableMapOf()
    val certificates: MutableMap<Int, FakeCertificate> = mutableMapOf()
    val requests: MutableList<AcmeRequest> = mutableListOf()
    var badNonces: Int = 0
    private var nonces: List<String> = emptyList()
    private var lastId: Int = 0

    fun nextId(): Int {
        lastId += 1
        return lastId
    }

    fun url(kind: String, id: Int): String = "$baseUrl/$kind/$id"

    fun url(kind: String): String = "$baseUrl/$kind"

    fun newNonce(): String {
        val nonce = random()
        nonces = (nonces + nonce).takeLast(MAXIMUM_NONCES)
        return nonce
    }

    fun useNonce(nonce: String?) {
        val isKnown = nonce in nonces
        nonces = nonces - nonce.orEmpty()
        val forced = badNonces.coerceAtMost(1)
        badNonces -= forced
        refuseUnless(condition = isKnown && forced == 0, type = AcmeProblemType.BadNonce)
    }

    fun token(): String = random() + random()

    fun <T : Any> found(records: Map<Int, T>, id: Int?): T = present(value = records[id], status = FakeReply.NOT_FOUND)

    private fun random(): String {
        val bytes = crypto.environment.random.bytes(NONCE_BYTES)
        return Base64.encode(bytes = bytes, alphabet = Base64Alphabet.Url, padding = false)
    }
}
