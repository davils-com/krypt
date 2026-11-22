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
import com.davils.krypt.acme.AcmeResponse
import com.davils.krypt.jose.JsonValue
import kotlinx.io.bytestring.encodeToByteString

internal class FakeRouter(private val state: FakeState) {
    private val requests = FakeRequests(state)
    private val accounts = FakeAccounts(state = state, requests = requests)
    private val orders = FakeOrders(state)
    private val certificates = FakeCertificates(state = state, orders = orders)

    private val routes: Map<String, suspend (AcmeRequest, List<String>) -> FakeReply> = mapOf(
        "GET directory" to { _, _ -> FakeReply.json(directory()) },
        "HEAD new-nonce" to { _, _ -> FakeReply(status = FakeReply.OK) },
        "GET renewal-info" to { _, segments -> certificates.renewal(segments) },
        "POST new-account" to { request, _ -> accounts.newAccount(requests.verify(request)) },
        "POST account" to { request, segments -> accounts.account(requests.verify(request), idOf(segments)) },
        "POST key-change" to { request, _ -> accounts.keyChange(requests.verify(request)) },
        "POST new-order" to { request, _ -> orders.newOrder(requests.verify(request)) },
        "POST order" to { request, segments -> orders.order(requests.verify(request), idOf(segments)) },
        "POST authz" to { request, segments -> orders.authorization(requests.verify(request), idOf(segments)) },
        "POST chall" to { request, segments -> orders.challenge(requests.verify(request), idOf(segments)) },
        "POST finalize" to { request, segments -> certificates.finalize(requests.verify(request), idOf(segments)) },
        "POST cert" to { request, segments -> certificates.certificate(requests.verify(request), segments) },
        "POST revoke-cert" to { request, _ -> certificates.revoke(requests.verify(request)) },
    )

    suspend fun route(request: AcmeRequest): AcmeResponse {
        state.requests += request
        val reply = try {
            dispatch(request)
        } catch (refusal: FakeRefusal) {
            problem(refusal)
        }
        val headers = reply.headers + (REPLAY_NONCE to state.newNonce())
        return AcmeResponse(status = reply.status, headers = headers, body = reply.body)
    }

    private suspend fun dispatch(request: AcmeRequest): FakeReply {
        val isLocal = request.url.startsWith(state.baseUrl + "/")
        refuseUnless(condition = isLocal, status = FakeReply.NOT_FOUND)
        val segments = request.url.substring(state.baseUrl.length + 1).split('/')
        val route = routes["${request.method.methodName} ${segments.first()}"]
        val found = route ?: refuse(type = AcmeProblemType.Malformed, status = FakeReply.NOT_FOUND)
        return found(request, segments)
    }

    private fun directory(): JsonValue.Object {
        val isBound = state.externalAccounts.isNotEmpty()
        val meta = json(
            "termsOfService" to text(state.url("terms")),
            "website" to text(state.baseUrl),
            "caaIdentities" to texts(listOf("acme.test")),
            "externalAccountRequired" to JsonValue.Bool(isBound),
        )
        return json(
            "newNonce" to text(state.url("new-nonce")),
            "newAccount" to text(state.url("new-account")),
            "newOrder" to text(state.url("new-order")),
            "revokeCert" to text(state.url("revoke-cert")),
            "keyChange" to text(state.url("key-change")),
            "renewalInfo" to text(state.url("renewal-info")),
            "meta" to meta,
        )
    }

    private fun problem(refusal: FakeRefusal): FakeReply {
        val body = json(
            "type" to text(refusal.type.urn),
            "detail" to text("The fake ACME server refused the request: ${refusal.type.code}"),
            "status" to JsonValue.Integer(refusal.status.toLong()),
        )
        return FakeReply(
            status = refusal.status,
            body = body.encode().encodeToByteString(),
            headers = listOf(FakeReply.CONTENT_TYPE to "application/problem+json"),
        )
    }

    companion object {
        private const val REPLAY_NONCE: String = "Replay-Nonce"

        fun idOf(segments: List<String>): Int? = segments.getOrNull(1)?.toIntOrNull()
    }
}
