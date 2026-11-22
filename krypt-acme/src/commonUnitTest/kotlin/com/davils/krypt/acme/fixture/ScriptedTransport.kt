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

package com.davils.krypt.acme.fixture

import com.davils.krypt.acme.AcmeMethod
import com.davils.krypt.acme.AcmeRequest
import com.davils.krypt.acme.AcmeResponse
import com.davils.krypt.acme.AcmeTransport
import kotlinx.io.bytestring.encodeToByteString

internal const val DIRECTORY_URL: String = "https://ca.test/directory"
internal const val NONCE: String = "oFvnlFP1wIhRlYS2jTaXbA"

internal val DIRECTORY: String = listOf(
    """{"newNonce":"https://ca.test/nonce","newAccount":"https://ca.test/account",""",
    """"newOrder":"https://ca.test/order","newAuthz":"https://ca.test/authz",""",
    """"revokeCert":"https://ca.test/revoke","keyChange":"https://ca.test/key",""",
    """"renewalInfo":"https://ca.test/renewal/","meta":{"termsOfService":"https://ca.test/terms",""",
    """"website":"https://ca.test","caaIdentities":["ca.test"],"externalAccountRequired":true}}""",
).joinToString(separator = "")

internal fun response(
    status: Int = 200,
    body: String = "",
    headers: List<Pair<String, String>> = emptyList(),
): AcmeResponse = AcmeResponse(status = status, headers = headers, body = body.encodeToByteString())

internal fun problemResponse(
    body: String,
    status: Int = 400,
    headers: List<Pair<String, String>> = emptyList(),
): AcmeResponse =
    response(status = status, body = body, headers = headers + ("Content-Type" to "application/problem+json"))

internal class ScriptedTransport(
    private val answers: List<AcmeResponse>,
    private val directory: AcmeResponse = response(body = DIRECTORY),
    private val nonce: AcmeResponse = response(headers = listOf("Replay-Nonce" to NONCE)),
    override val isPlainHttpAllowed: Boolean = false,
) : AcmeTransport {
    val requests: MutableList<AcmeRequest> = mutableListOf()
    private var next: Int = 0

    override suspend fun exchange(request: AcmeRequest): AcmeResponse {
        requests += request
        return when (request.method) {
            AcmeMethod.Head -> nonce
            AcmeMethod.Get, AcmeMethod.Post -> answer(request)
        }
    }

    private fun answer(request: AcmeRequest): AcmeResponse {
        if (request.url == DIRECTORY_URL) return directory
        val answer = answers[next.coerceAtMost(answers.size - 1)]
        next += 1
        return answer
    }
}
