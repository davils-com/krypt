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

import com.davils.kontinuity.retry.RetryConfig
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.map
import com.davils.kore.core.text.SafeText
import com.davils.krypt.acme.account.AccountKey
import com.davils.krypt.acme.account.AcmeAccount
import com.davils.krypt.acme.account.ExternalAccountBinding
import com.davils.krypt.acme.internal.CheckedSession
import com.davils.krypt.acme.internal.Exchange
import com.davils.krypt.acme.internal.Signing
import com.davils.krypt.acme.internal.Tokens
import com.davils.krypt.acme.internal.TransportRetries
import com.davils.krypt.acme.internal.Urls
import com.davils.krypt.acme.internal.base64Url
import com.davils.krypt.acme.internal.bytesOf
import com.davils.krypt.acme.internal.refuse
import com.davils.krypt.acme.internal.supported
import com.davils.krypt.acme.internal.text
import com.davils.krypt.acme.order.Challenges
import com.davils.krypt.acme.renewal.CertificateIdentifiers
import com.davils.krypt.acme.renewal.RenewalInfo
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jws.JwsSigner
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.RevocationReason

/**
 * The client logic of ACME by RFC 8555, over a [transport] of the application: krypt opens no socket and starts no
 * timer.
 *
 * The client reads the directory once and keeps it, keeps a bounded pool of the nonces of every response, signs each
 * request as a flattened JWS with the `url` and `nonce` headers and repeats a request the server refused with
 * `badNonce` up to [AcmeLimits.maximumNonceRetries] times. A transport that throws, such as a dropped connection, is
 * tried again by the retry of kontinuity [transportRetry], [DEFAULT_TRANSPORT_RETRY] unless another is given; a signed
 * request sent again carries the nonce it carried before, which the server refuses with `badNonce` if it saw it
 * already, so a repeated request never acts twice. Every answer of the server is checked against [limits];
 * every URL it names must be absolute `https`, or `http` where the transport allows it. A refusal of the server
 * becomes an [AcmeProblem], a refusal of the client an [AcmeError]: no operation throws for what the server sends.
 *
 * Operations of an account run on an [AcmeSession]. The client is safe to share between coroutines and threads; the
 * nonce pool and the directory are its only state.
 *
 * @param transport the HTTP client of the application.
 * @property directoryUrl the URL of the directory of the server.
 * @property crypto the primitives, for signatures, thumbprints and certificates.
 * @property limits the limits on what the server sends.
 * @property transportRetry how a request whose transport threw is tried again, with its attempts, backoff and jitter,
 *   or `null` to try each request once; its events and meters reach the environment of [crypto].
 * @constructor Prepares a client; it sends nothing yet.
 * @throws IllegalArgumentException if [directoryUrl] is not absolute `https`, or `http` where the transport allows
 *   it.
 * @since 1.0.0
 */
public class AcmeClient(
    transport: AcmeTransport,
    public val directoryUrl: String,
    public val crypto: Crypto,
    public val limits: AcmeLimits,
    public val transportRetry: RetryConfig?,
) {
    internal val exchange: Exchange = Exchange(
        transport = transport,
        directoryUrl = Urls.checked(
            text = directoryUrl,
            isHttpAllowed = transport.isPlainHttpAllowed,
            maximumLength = limits.maximumUrlLength,
        ),
        crypto = crypto,
        limits = limits,
        retry = transportRetry?.let { config -> TransportRetries.of(config = config, crypto = crypto) },
    )

    /**
     * What answers challenges, over [crypto].
     *
     * @since 1.0.0
     */
    public val challenges: Challenges = Challenges(crypto)

    /**
     * Prepares a client that tries a request whose transport threw again by [DEFAULT_TRANSPORT_RETRY].
     *
     * @param transport the HTTP client of the application.
     * @param directoryUrl the URL of the directory of the server.
     * @param crypto the primitives, for signatures, thumbprints and certificates.
     * @param limits the limits on what the server sends.
     * @throws IllegalArgumentException if [directoryUrl] is not absolute `https`, or `http` where the transport allows
     *   it.
     * @since 1.0.0
     */
    public constructor(
        transport: AcmeTransport,
        directoryUrl: String,
        crypto: Crypto,
        limits: AcmeLimits = AcmeLimits.Default,
    ) : this(
        transport = transport,
        directoryUrl = directoryUrl,
        crypto = crypto,
        limits = limits,
        transportRetry = DEFAULT_TRANSPORT_RETRY,
    )

    /**
     * Returns the directory, read once and then kept.
     *
     * @return the directory, or why it could not be read.
     * @since 1.0.0
     */
    public suspend fun directory(): Outcome<AcmeDirectory, AcmeFailure> = exchange.directory()

    /**
     * Creates an account for [key], by RFC 8555 section 7.3, or finds the account the key already has.
     *
     * @param key the account key, sent as `jwk`.
     * @param contacts the contact URLs, such as `mailto:admin@example.org`.
     * @param isTermsOfServiceAgreed whether the holder agrees to the terms of service of the directory.
     * @param binding the external account binding of section 7.3.4, which the server may require.
     * @return the account, with [AcmeAccount.isCreated] telling whether it is new, or why it failed.
     * @throws IllegalArgumentException if a contact is no interchangeable Unicode text.
     * @since 1.0.0
     */
    public suspend fun newAccount(
        key: AccountKey,
        contacts: List<String> = emptyList(),
        isTermsOfServiceAgreed: Boolean = false,
        binding: ExternalAccountBinding? = null,
    ): Outcome<AcmeAccount, AcmeFailure> {
        val contactMembers = contacts.map { contact -> text(contact) }
        return exchange.directory().flatMap { directory ->
            val members = listOfNotNull(
                (TERMS to JsonValue.Bool(true)).takeIf { isTermsOfServiceAgreed },
                (CONTACT to JsonValue.Array(contactMembers)).takeIf { contacts.isNotEmpty() },
                binding?.let { found -> EXTERNAL_BINDING to bindingOf(key, found, directory.newAccount) },
            )
            accountAt(url = directory.newAccount, key = key, payload = JsonValue.Object(members))
        }
    }

    /**
     * Finds the account of [key] with `onlyReturnExisting`, by RFC 8555 section 7.3.1.
     *
     * @param key the account key.
     * @return the account, or the problem [AcmeProblemType.AccountDoesNotExist] if the key has none.
     * @since 1.0.0
     */
    public suspend fun findAccount(key: AccountKey): Outcome<AcmeAccount, AcmeFailure> =
        exchange.directory().flatMap { directory ->
            val payload = JsonValue.Object.of(ONLY_RETURN_EXISTING to JsonValue.Bool(true))
            accountAt(url = directory.newAccount, key = key, payload = payload)
        }

    /**
     * Returns a session for the account at [accountUrl], whose requests [key] signs with the account URL as `kid`.
     *
     * @param key the account key.
     * @param accountUrl the URL of the account, from [newAccount] or [findAccount].
     * @return the session; it sends nothing yet.
     * @throws IllegalArgumentException if [accountUrl] is not absolute `https`, or `http` where the transport allows
     *   it.
     * @since 1.0.0
     */
    public fun session(key: AccountKey, accountUrl: String): AcmeSession =
        AcmeSession(CheckedSession(client = this, key = key, accountUrl = exchange.readers.url(accountUrl)))

    /**
     * Revokes [certificate] with a request signed by its own key, by RFC 8555 section 7.6, without an account.
     *
     * @param certificate the certificate.
     * @param certificateKey the key pair of the certificate, sent as `jwk`.
     * @param reason the reason code of RFC 5280, or null.
     * @return success, or why the revocation failed, [AcmeError.Unsupported] if the server offers no revocation.
     * @since 1.0.0
     */
    public suspend fun revoke(
        certificate: Certificate,
        certificateKey: AccountKey,
        reason: RevocationReason? = null,
    ): Outcome<Unit, AcmeFailure> {
        val signing = Signing.ByKey(certificateKey)
        return revoke(certificate = certificate, reason = reason, signing = signing)
    }

    /**
     * Returns the renewal information of [certificate], by RFC 9773.
     *
     * @param certificate the certificate.
     * @return the information, [AcmeError.Unsupported] if the certificate has no authority key identifier or the
     *   server offers no renewal information, or why it failed.
     * @since 1.0.0
     */
    public suspend fun renewalInfo(certificate: Certificate): Outcome<RenewalInfo, AcmeFailure> {
        val identifier = CertificateIdentifiers.of(certificate) ?: return Outcome.Failure(AcmeError.Unsupported)
        return renewalInfo(identifier)
    }

    /**
     * Returns the renewal information of the certificate with the identifier [certificateId], by RFC 9773.
     *
     * @param certificateId the certificate identifier of [CertificateIdentifiers].
     * @return the information, [AcmeError.Unsupported] if the server offers none, or why it failed.
     * @throws IllegalArgumentException if [certificateId] is no certificate identifier.
     * @since 1.0.0
     */
    public suspend fun renewalInfo(certificateId: String): Outcome<RenewalInfo, AcmeFailure> {
        require(Tokens.isCertificateId(certificateId)) { "${SafeText.quoted(certificateId)} is no certificate id" }
        val base = exchange.directory().flatMap { directory -> supported(directory.renewalInfo) }
        val reply = base.flatMap { found -> exchange.get(found.trimEnd('/') + "/" + certificateId) }
        return reply.flatMap { found ->
            exchange.json(found) { json ->
                exchange.readers.renewal(json = json, certificateId = certificateId, retryAfter = found.retryAfter)
            }
        }
    }

    internal suspend fun revoke(
        certificate: Certificate,
        reason: RevocationReason?,
        signing: Signing,
    ): Outcome<Unit, AcmeFailure> {
        val members = listOfNotNull(
            CERTIFICATE to text(base64Url(certificate.encoded)),
            reason?.let { found -> REASON to JsonValue.Integer(found.code.toLong()) },
        )
        val payload = bytesOf(JsonValue.Object(members))
        val url = exchange.directory().flatMap { directory -> supported(directory.revokeCertificate) }
        val reply = url.flatMap { found -> exchange.post(url = found, payload = payload, signing = signing) }
        return reply.map { _ -> }
    }

    private suspend fun accountAt(
        url: String,
        key: AccountKey,
        payload: JsonValue.Object,
    ): Outcome<AcmeAccount, AcmeFailure> {
        val reply = exchange.post(
            url = url,
            payload = bytesOf(payload),
            signing = Signing.ByKey(key),
            statuses = Exchange.OK_OR_CREATED,
        )
        return reply.flatMap { found ->
            exchange.json(found) { json ->
                val location = found.location ?: refuse(AcmeError.Malformed)
                val status = found.response.status
                exchange.readers.account(json = json, url = location, isCreated = status == Exchange.CREATED_STATUS)
            }
        }
    }

    private suspend fun bindingOf(key: AccountKey, binding: ExternalAccountBinding, url: String): JsonValue.Object {
        val jwk = bytesOf(exchange.jwkOf(key.publicKey))
        val signer = JwsSigner(
            key = JoseKey.Secret(binding.key),
            algorithm = binding.algorithm,
            header = JsonValue.Object.of(KEY_ID to text(binding.keyId)),
        )
        return exchange.signedWithMac(payload = jwk, url = url, signer = signer)
    }

    /**
     * Shows the directory URL, escaped.
     *
     * @return the client as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeClient(${SafeText.text(directoryUrl)})"

    /**
     * The defaults of a client.
     *
     * @since 1.2.0
     */
    public companion object {
        /**
         * How a request whose transport threw is tried again unless another retry is given: 3 attempts with an
         * exponential backoff from 200 milliseconds to 2 seconds, spread by a proportional jitter.
         *
         * @since 1.2.0
         */
        public val DEFAULT_TRANSPORT_RETRY: RetryConfig = TransportRetries.DEFAULT

        private const val TERMS: String = "termsOfServiceAgreed"
        private const val CONTACT: String = "contact"
        private const val EXTERNAL_BINDING: String = "externalAccountBinding"
        private const val ONLY_RETURN_EXISTING: String = "onlyReturnExisting"
        private const val CERTIFICATE: String = "certificate"
        private const val REASON: String = "reason"
        private const val KEY_ID: String = "kid"
    }
}
