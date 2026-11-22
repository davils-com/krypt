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

package com.davils.krypt.acme

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.getOrNull
import com.davils.kore.core.outcome.map
import com.davils.kore.core.text.SafeText
import com.davils.krypt.acme.account.AccountKey
import com.davils.krypt.acme.account.AcmeAccount
import com.davils.krypt.acme.internal.CheckedSession
import com.davils.krypt.acme.internal.Exchange
import com.davils.krypt.acme.internal.Polling
import com.davils.krypt.acme.internal.Reply
import com.davils.krypt.acme.internal.Signing
import com.davils.krypt.acme.internal.Tokens
import com.davils.krypt.acme.internal.base64Url
import com.davils.krypt.acme.internal.bytesOf
import com.davils.krypt.acme.internal.reading
import com.davils.krypt.acme.internal.refuse
import com.davils.krypt.acme.internal.supported
import com.davils.krypt.acme.internal.text
import com.davils.krypt.acme.order.AcmeAuthorization
import com.davils.krypt.acme.order.AcmeChallenge
import com.davils.krypt.acme.order.AcmeOrder
import com.davils.krypt.acme.order.CertificateChain
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.request.CertificationRequest
import com.davils.krypt.x509.request.CertificationRequests
import kotlinx.coroutines.delay
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/**
 * The operations of one ACME account: every request is signed by [key] with [accountUrl] as `kid`, by RFC 8555
 * section 6.2.
 *
 * Reading a resource is a POST-as-GET. Each resource the server returns carries the `Retry-After` of its response;
 * the caller decides when to poll again. [awaitOrder] and [awaitAuthorization] poll for the caller, suspending with
 * `delay` in the context of the caller, never on a timer of krypt.
 *
 * A session is immutable and safe to share between coroutines; it shares the nonce pool of its client.
 *
 * @property client the client.
 * @property key the account key.
 * @property accountUrl the URL of the account.
 * @since 1.0.0
 */
public class AcmeSession private constructor(
    public val client: AcmeClient,
    public val key: AccountKey,
    public val accountUrl: String,
) {
    private val exchange: Exchange = client.exchange
    private val signing: Signing = Signing.ByKeyId(key = key, accountUrl = accountUrl)

    internal constructor(checked: CheckedSession) :
        this(client = checked.client, key = checked.key, accountUrl = checked.accountUrl)

    /**
     * Reads the account.
     *
     * @return the account, or why it failed.
     * @since 1.0.0
     */
    public suspend fun account(): Outcome<AcmeAccount, AcmeFailure> = accountWith(ByteString())

    /**
     * Replaces the contact URLs of the account.
     *
     * @param contacts the new contact URLs; empty removes them all.
     * @return the account, or why it failed.
     * @throws IllegalArgumentException if a contact is no interchangeable Unicode text.
     * @since 1.0.0
     */
    public suspend fun updateAccount(contacts: List<String>): Outcome<AcmeAccount, AcmeFailure> {
        val payload = JsonValue.Object.of(CONTACT to JsonValue.Array(contacts.map { contact -> text(contact) }))
        return accountWith(bytesOf(payload))
    }

    /**
     * Deactivates the account for good, by RFC 8555 section 7.3.6.
     *
     * @return the account, now [AcmeStatus.Deactivated], or why it failed.
     * @since 1.0.0
     */
    public suspend fun deactivateAccount(): Outcome<AcmeAccount, AcmeFailure> = accountWith(DEACTIVATION)

    /**
     * Rolls the account over to [newKey], by RFC 8555 section 7.3.5: an inner JWS signed by [newKey] with its `jwk`,
     * carrying the account URL and the old key, inside a request signed by [key].
     *
     * @param newKey the new account key.
     * @return a session with [newKey], [AcmeError.Unsupported] if the server offers no key change, or why it failed.
     * @since 1.0.0
     */
    public suspend fun changeKey(newKey: AccountKey): Outcome<AcmeSession, AcmeFailure> {
        val inner = JsonValue.Object.of(ACCOUNT to text(accountUrl), OLD_KEY to exchange.jwkOf(key.publicKey))
        val url = exchange.directory().flatMap { directory -> supported(directory.keyChange) }
        val reply = url.flatMap { found ->
            val nested = exchange.signed(
                payload = bytesOf(inner),
                url = found,
                nonce = null,
                signing = Signing.ByKey(newKey),
            )
            exchange.post(url = found, payload = bytesOf(nested), signing = signing)
        }
        return reply.map { _ -> AcmeSession(CheckedSession(client = client, key = newKey, accountUrl = accountUrl)) }
    }

    /**
     * Places a new order, by RFC 8555 section 7.4, with RFC 8738 for IP addresses and the `replaces` member of RFC
     * 9773.
     *
     * @param identifiers the identifiers the certificate is for.
     * @param notBefore the requested start of the validity, or null.
     * @param notAfter the requested end of the validity, or null.
     * @param replaces the certificate identifier of the certificate the order replaces, or null.
     * @return the order, or why it failed.
     * @throws IllegalArgumentException if [identifiers] is empty, [notAfter] is not after [notBefore] or [replaces]
     *   is no certificate identifier.
     * @since 1.0.0
     */
    public suspend fun newOrder(
        identifiers: List<AcmeIdentifier>,
        notBefore: Instant? = null,
        notAfter: Instant? = null,
        replaces: String? = null,
    ): Outcome<AcmeOrder, AcmeFailure> {
        require(identifiers.isNotEmpty()) { "An order names at least one identifier" }
        require(notBefore == null || notAfter == null || notBefore < notAfter) { "The validity ends after it starts" }
        require(replaces == null || Tokens.isCertificateId(replaces)) { "replaces is a certificate identifier" }
        val members = listOfNotNull(
            IDENTIFIERS to JsonValue.Array(identifiers.map { identifier -> Polling.identifierOf(identifier) }),
            notBefore?.let { found -> NOT_BEFORE to text(found.toString()) },
            notAfter?.let { found -> NOT_AFTER to text(found.toString()) },
            replaces?.let { found -> REPLACES to text(found) },
        )
        val payload = bytesOf(JsonValue.Object(members))
        val reply = exchange.directory().flatMap { directory ->
            post(url = directory.newOrder, payload = payload, statuses = Exchange.CREATED)
        }
        return reply.flatMap { found ->
            exchange.json(found) { json ->
                val location = found.location ?: refuse(AcmeError.Malformed)
                exchange.readers.order(json = json, url = location, retryAfter = found.retryAfter)
            }
        }
    }

    /**
     * Reads the order at [url].
     *
     * @param url the URL of the order.
     * @return the order, [AcmeError.InsecureUrl] if [url] is not acceptable, or why it failed.
     * @since 1.0.0
     */
    public suspend fun order(url: String): Outcome<AcmeOrder, AcmeFailure> = post(url, ByteString()).flatMap { reply ->
        exchange.json(reply) { json -> exchange.readers.order(json = json, url = url, retryAfter = reply.retryAfter) }
    }

    /**
     * Reads the authorization at [url].
     *
     * @param url the URL of the authorization.
     * @return the authorization, [AcmeError.InsecureUrl] if [url] is not acceptable, or why it failed.
     * @since 1.0.0
     */
    public suspend fun authorization(url: String): Outcome<AcmeAuthorization, AcmeFailure> =
        authorizationWith(url = url, payload = ByteString())

    /**
     * Deactivates the authorization at [url], by RFC 8555 section 7.5.2.
     *
     * @param url the URL of the authorization.
     * @return the authorization, now [AcmeStatus.Deactivated], or why it failed.
     * @since 1.0.0
     */
    public suspend fun deactivateAuthorization(url: String): Outcome<AcmeAuthorization, AcmeFailure> =
        authorizationWith(url = url, payload = DEACTIVATION)

    /**
     * Reads the challenge at [url].
     *
     * @param url the URL of the challenge.
     * @return the challenge, [AcmeError.InsecureUrl] if [url] is not acceptable, or why it failed.
     * @since 1.0.0
     */
    public suspend fun challenge(url: String): Outcome<AcmeChallenge, AcmeFailure> =
        challengeWith(url = url, payload = ByteString())

    /**
     * Tells the server that [challenge] is ready to be validated, by RFC 8555 section 7.5.1. Provision the response
     * first: the key authorization from [keyAuthorization] at the place the challenge type names.
     *
     * @param challenge the challenge.
     * @return the challenge as the server now sees it, or why it failed.
     * @since 1.0.0
     */
    public suspend fun respond(challenge: AcmeChallenge): Outcome<AcmeChallenge, AcmeFailure> =
        challengeWith(url = challenge.url, payload = bytesOf(JsonValue.Object.Empty))

    /**
     * Returns the key authorization of [challenge] for [key].
     *
     * @param challenge a challenge of a type krypt knows, with its token.
     * @return the key authorization.
     * @throws IllegalArgumentException if the challenge has no token.
     * @since 1.0.0
     */
    public suspend fun keyAuthorization(challenge: AcmeChallenge): String {
        val token = requireNotNull(challenge.token) { "The challenge has no token" }
        return client.challenges.keyAuthorization(token = token, accountKey = key.publicKey)
    }

    /**
     * Finalizes [order] with [request], by RFC 8555 section 7.4.
     *
     * @param order the order, which should be [AcmeStatus.Ready].
     * @param request the certification request for the identifiers of the order.
     * @return the order, now [AcmeStatus.Processing] or [AcmeStatus.Valid], or why it failed.
     * @since 1.0.0
     */
    public suspend fun finalize(order: AcmeOrder, request: CertificationRequest): Outcome<AcmeOrder, AcmeFailure> {
        val payload = JsonValue.Object.of(CSR to text(base64Url(request.encoded)))
        return post(url = order.finalize, payload = bytesOf(payload)).flatMap { reply ->
            exchange.json(reply) { json ->
                exchange.readers.order(json = json, url = order.url, retryAfter = reply.retryAfter)
            }
        }
    }

    /**
     * Finalizes [order] with a certification request krypt-x509 makes and [signer] signs: an empty subject and a
     * critical subject alternative name extension with every identifier of the order.
     *
     * @param order the order, which should be [AcmeStatus.Ready].
     * @param signer the key of the certificate, which signs the request.
     * @return the order, now [AcmeStatus.Processing] or [AcmeStatus.Valid], or why it failed.
     * @since 1.0.0
     */
    public suspend fun finalize(order: AcmeOrder, signer: Signer): Outcome<AcmeOrder, AcmeFailure> {
        val names = order.identifiers.map { identifier -> identifier.generalName }
        val request = CertificationRequests(client.crypto).create(signer) {
            extensions { subjectAlternativeNames(names = names, critical = true) }
        }
        return finalize(order = order, request = request)
    }

    /**
     * Downloads the certificate chain at [url] as `application/pem-certificate-chain`, by RFC 8555 section 7.4.2,
     * with the URLs of its alternate chains.
     *
     * @param url the URL of the certificate, from the order or an alternate.
     * @return the chain, decoded but not validated, or why it failed.
     * @since 1.0.0
     */
    public suspend fun certificate(url: String): Outcome<CertificateChain, AcmeFailure> =
        post(url = url, payload = ByteString(), accept = PEM_CHAIN).flatMap { reply ->
            reading { exchange.readers.chain(body = reply.response.body, links = reply.links) }
        }

    /**
     * Revokes [certificate] with a request of the account, by RFC 8555 section 7.6.
     *
     * @param certificate the certificate, issued to this account.
     * @param reason the reason code of RFC 5280, or null.
     * @return success, [AcmeError.Unsupported] if the server offers no revocation, or why it failed.
     * @since 1.0.0
     */
    public suspend fun revoke(certificate: Certificate, reason: RevocationReason? = null): Outcome<Unit, AcmeFailure> =
        client.revoke(certificate = certificate, reason = reason, signing = signing)

    /**
     * Polls [order] while it is [AcmeStatus.Pending] or [AcmeStatus.Processing], waiting as long as the
     * `Retry-After` of each response asks or [interval] where none does.
     *
     * @param order the order.
     * @param maximumPolls how often to poll at most, 1 to 1000.
     * @param interval the wait without a `Retry-After`; one second by default.
     * @return the order once it left those states, [AcmeError.PollsExhausted] if it did not in time, or why a poll
     *   failed.
     * @throws IllegalArgumentException if [maximumPolls] is out of range or [interval] is negative.
     * @since 1.0.0
     */
    public suspend fun awaitOrder(
        order: AcmeOrder,
        maximumPolls: Int = DEFAULT_POLLS,
        interval: Duration = DEFAULT_INTERVAL,
    ): Outcome<AcmeOrder, AcmeFailure> {
        Polling.check(maximumPolls = maximumPolls, interval = interval)
        var current = order
        var remaining = maximumPolls
        while (current.status in WAITING_ORDER && remaining > 0) {
            delay(current.retryAfter ?: interval)
            val polled = this.order(current.url)
            current = polled.getOrNull() ?: return polled
            remaining -= 1
        }
        return Polling.settled(value = current, isWaiting = current.status in WAITING_ORDER)
    }

    /**
     * Polls [authorization] while it is [AcmeStatus.Pending], waiting as long as the `Retry-After` of each response
     * asks or [interval] where none does.
     *
     * @param authorization the authorization.
     * @param maximumPolls how often to poll at most, 1 to 1000.
     * @param interval the wait without a `Retry-After`; one second by default.
     * @return the authorization once it left the state, [AcmeError.PollsExhausted] if it did not in time, or why a
     *   poll failed.
     * @throws IllegalArgumentException if [maximumPolls] is out of range or [interval] is negative.
     * @since 1.0.0
     */
    public suspend fun awaitAuthorization(
        authorization: AcmeAuthorization,
        maximumPolls: Int = DEFAULT_POLLS,
        interval: Duration = DEFAULT_INTERVAL,
    ): Outcome<AcmeAuthorization, AcmeFailure> {
        Polling.check(maximumPolls = maximumPolls, interval = interval)
        var current = authorization
        var remaining = maximumPolls
        while (current.status == AcmeStatus.Pending && remaining > 0) {
            delay(current.retryAfter ?: interval)
            val polled = this.authorization(current.url)
            current = polled.getOrNull() ?: return polled
            remaining -= 1
        }
        return Polling.settled(value = current, isWaiting = current.status == AcmeStatus.Pending)
    }

    /**
     * Shows the account URL and the key, never the key material.
     *
     * @return the session as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeSession(${SafeText.text(accountUrl)}, $key)"

    private suspend fun accountWith(payload: ByteString): Outcome<AcmeAccount, AcmeFailure> =
        post(url = accountUrl, payload = payload).flatMap { reply ->
            exchange.json(reply) { json -> exchange.readers.account(json = json, url = accountUrl, isCreated = false) }
        }

    private suspend fun authorizationWith(url: String, payload: ByteString): Outcome<AcmeAuthorization, AcmeFailure> =
        post(url = url, payload = payload).flatMap { reply ->
            exchange.json(reply) { json ->
                exchange.readers.authorization(json = json, url = url, retryAfter = reply.retryAfter)
            }
        }

    private suspend fun challengeWith(url: String, payload: ByteString): Outcome<AcmeChallenge, AcmeFailure> =
        post(url = url, payload = payload).flatMap { reply ->
            exchange.json(reply) { json -> exchange.readers.challenge(json = json, retryAfter = reply.retryAfter) }
        }

    private suspend fun post(
        url: String,
        payload: ByteString,
        statuses: Set<Int> = Exchange.OK,
        accept: String? = null,
    ): Outcome<Reply, AcmeFailure> = reading { exchange.readers.url(url) }.flatMap { checked ->
        exchange.post(url = checked, payload = payload, signing = signing, statuses = statuses, accept = accept)
    }

    private companion object {
        const val CONTACT: String = "contact"
        const val ACCOUNT: String = "account"
        const val OLD_KEY: String = "oldKey"
        const val IDENTIFIERS: String = "identifiers"
        const val NOT_BEFORE: String = "notBefore"
        const val NOT_AFTER: String = "notAfter"
        const val REPLACES: String = "replaces"
        const val CSR: String = "csr"
        const val PEM_CHAIN: String = "application/pem-certificate-chain"
        const val DEFAULT_POLLS: Int = 30
        val DEFAULT_INTERVAL: Duration = 1.seconds
        val WAITING_ORDER: Set<AcmeStatus> = setOf(AcmeStatus.Pending, AcmeStatus.Processing)
        val DEACTIVATION: ByteString = """{"status":"deactivated"}""".encodeToByteString()
    }
}
