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

import com.davils.krypt.acme.AcmeRequest
import com.davils.krypt.acme.AcmeResponse
import com.davils.krypt.acme.AcmeTransport
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * An ACME server in memory for tests, by RFC 8555, RFC 8737 and RFC 9773: an [AcmeTransport] that answers the
 * client of krypt-acme without a network.
 *
 * It serves the directory with its `meta` object, fresh nonces on every response, accounts with an optional external
 * account binding, key rollover, orders for DNS names and IP addresses with `notBefore`, `notAfter` and `replaces`,
 * authorizations that become valid as soon as the client responds to one of their challenges, finalization that
 * issues with krypt-x509 from a CA of its own, certificate chains with an alternate chain, revocation by the account
 * or by the key of the certificate, and renewal information. It checks every request as a server must: the flattened
 * JWS, its signature, the `url`, the nonce, `jwk` or `kid`, and that a resource belongs to the account.
 *
 * Never use it outside tests: it validates no challenge and issues for every identifier. It serves one request at a
 * time and is safe to share between coroutines.
 *
 * @property crypto the primitives, for verification and issuance.
 * @property baseUrl the URL every resource lives under.
 * @param externalAccounts the MAC keys of the external accounts by key id; when there are any, a new account needs
 *   an external account binding.
 * @param processingPolls how often the client polls a finalized order before it becomes valid; 0 issues at once.
 * @constructor Starts an empty server.
 * @since 1.0.0
 */
public class FakeAcmeServer(
    public val crypto: Crypto,
    public val baseUrl: String = DEFAULT_BASE_URL,
    externalAccounts: Map<String, SecretKey> = emptyMap(),
    processingPolls: Int = 0,
) : AcmeTransport {
    private val mutex = Mutex()
    private val state = FakeState(
        crypto = crypto,
        baseUrl = baseUrl,
        externalAccounts = externalAccounts.toMap(),
        processingPolls = processingPolls,
    )
    private val router = FakeRouter(state)

    /**
     * The URL of the directory.
     *
     * @since 1.0.0
     */
    public val directoryUrl: String = "$baseUrl/directory"

    /**
     * Whether [baseUrl] is plain `http`, which the client then accepts.
     *
     * @since 1.0.0
     */
    override val isPlainHttpAllowed: Boolean = baseUrl.startsWith(HTTP)

    /**
     * Returns every request the server received, in order.
     *
     * @return the requests.
     * @since 1.0.0
     */
    public suspend fun requests(): List<AcmeRequest> = mutex.withLock { state.requests.toList() }

    /**
     * Refuses the next [count] signed requests with `badNonce`, whatever their nonce.
     *
     * @param count how many requests to refuse.
     * @throws IllegalArgumentException if [count] is negative.
     * @since 1.0.0
     */
    public suspend fun rejectNextNonces(count: Int) {
        require(count >= 0) { "A count is not negative" }
        mutex.withLock { state.badNonces = count }
    }

    /**
     * Answers [request].
     *
     * @param request the request of the client.
     * @return the response; a refusal is a problem document.
     * @since 1.0.0
     */
    override suspend fun exchange(request: AcmeRequest): AcmeResponse = mutex.withLock { router.route(request) }

    /**
     * Shows the base URL.
     *
     * @return the server as text.
     * @since 1.0.0
     */
    override fun toString(): String = "FakeAcmeServer($baseUrl)"

    /**
     * The defaults of the server.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default base URL.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_BASE_URL: String = "https://acme.test"

        private const val HTTP: String = "http://"
    }
}
