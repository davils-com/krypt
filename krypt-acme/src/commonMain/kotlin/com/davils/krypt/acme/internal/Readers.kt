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

package com.davils.krypt.acme.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.acme.AcmeDirectory
import com.davils.krypt.acme.AcmeError
import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.acme.AcmeLimits
import com.davils.krypt.acme.AcmeProblem
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.AcmeStatus
import com.davils.krypt.acme.DirectoryMeta
import com.davils.krypt.acme.IdentifierType
import com.davils.krypt.acme.account.AcmeAccount
import com.davils.krypt.acme.order.AcmeAuthorization
import com.davils.krypt.acme.order.AcmeChallenge
import com.davils.krypt.acme.order.AcmeOrder
import com.davils.krypt.acme.order.CertificateChain
import com.davils.krypt.acme.order.ChallengeType
import com.davils.krypt.acme.renewal.RenewalInfo
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration
import kotlin.time.Instant

private const val ABOUT_BLANK: String = "about:blank"
private const val CERTIFICATE_LABEL: String = "CERTIFICATE"
private const val ALTERNATE: String = "alternate"
private const val MAXIMUM_TIME_LENGTH: Int = 64
private const val LOWEST_STATUS: Long = 100L
private const val HIGHEST_STATUS: Long = 599L

internal class Readers(
    private val limits: AcmeLimits,
    private val isHttpAllowed: Boolean,
    private val certificates: Certificates,
) {
    fun url(text: String): String =
        Urls.checked(text = text, isHttpAllowed = isHttpAllowed, maximumLength = limits.maximumUrlLength)

    fun directory(json: JsonValue.Object): AcmeDirectory {
        val meta = json.member("meta") ?: JsonValue.Object.Empty
        return AcmeDirectory(
            newNonce = json.requiredUrl("newNonce"),
            newAccount = json.requiredUrl("newAccount"),
            newOrder = json.requiredUrl("newOrder"),
            newAuthorization = json.optionalUrl("newAuthz"),
            revokeCertificate = json.optionalUrl("revokeCert"),
            keyChange = json.optionalUrl("keyChange"),
            renewalInfo = json.optionalUrl("renewalInfo"),
            meta = DirectoryMeta(
                termsOfService = meta.optionalUrl("termsOfService"),
                website = meta.optionalUrl("website"),
                caaIdentities = meta.texts(name = "caaIdentities", maximum = limits.maximumEntries).orEmpty(),
                isExternalAccountRequired = meta.bool("externalAccountRequired") == true,
            ),
        )
    }

    fun account(json: JsonValue.Object, url: String, isCreated: Boolean): AcmeAccount = AcmeAccount(
        url = url,
        status = status(json = json, allowed = ACCOUNT_STATUSES),
        contacts = json.texts(name = "contact", maximum = limits.maximumEntries).orEmpty(),
        isTermsOfServiceAgreed = json.bool("termsOfServiceAgreed"),
        orders = json.optionalUrl("orders"),
        isCreated = isCreated,
    )

    fun order(json: JsonValue.Object, url: String, retryAfter: Duration?): AcmeOrder {
        val identifiers = required(json.items(name = "identifiers", maximum = limits.maximumEntries))
        val authorizations = required(json.texts(name = "authorizations", maximum = limits.maximumEntries))
        val replaces = json.text("replaces")
        refuseUnless(identifiers.isNotEmpty() && (replaces == null || Tokens.isCertificateId(replaces)))
        return AcmeOrder(
            url = url,
            status = status(json = json, allowed = ORDER_STATUSES),
            identifiers = identifiers.map { item -> identifier(item.asObject()) },
            authorizations = authorizations.map { item -> url(item) },
            finalize = json.requiredUrl("finalize"),
            certificate = json.optionalUrl("certificate"),
            times = OrderTimes(
                expires = json.optionalTime("expires"),
                notBefore = json.optionalTime("notBefore"),
                notAfter = json.optionalTime("notAfter"),
            ),
            error = json.member("error")?.let { found -> problem(json = found, retryAfter = null, isNested = true) },
            replaces = replaces,
            retryAfter = retryAfter,
        )
    }

    fun authorization(json: JsonValue.Object, url: String, retryAfter: Duration?): AcmeAuthorization {
        val challenges = required(json.items(name = "challenges", maximum = limits.maximumEntries))
        return AcmeAuthorization(
            url = url,
            identifier = identifier(required(json.member("identifier"))),
            status = status(json = json, allowed = AUTHORIZATION_STATUSES),
            challenges = challenges.map { item -> challenge(json = item.asObject(), retryAfter = null) },
            expires = json.optionalTime("expires"),
            isWildcard = json.bool("wildcard") == true,
            retryAfter = retryAfter,
        )
    }

    fun challenge(json: JsonValue.Object, retryAfter: Duration?): AcmeChallenge {
        val type = json.requiredText("type")
        val kind = ChallengeType.of(type)
        val token = json.text("token")
        refuseUnless(kind == null || (token != null && Tokens.isValid(token)))
        return AcmeChallenge(
            url = json.requiredUrl("url"),
            type = type,
            kind = kind,
            status = status(json = json, allowed = CHALLENGE_STATUSES),
            token = token.takeIf { kind != null },
            validated = json.optionalTime("validated"),
            error = json.member("error")?.let { found -> problem(json = found, retryAfter = null, isNested = true) },
            retryAfter = retryAfter,
        )
    }

    fun identifier(json: JsonValue.Object): AcmeIdentifier {
        val type = required(IdentifierType.of(json.requiredText("type")))
        return AcmeIdentifier(type = type, value = json.requiredText("value"))
    }

    fun problem(json: JsonValue.Object, retryAfter: Duration?, isNested: Boolean = false): AcmeProblem {
        val type = json.text("type") ?: ABOUT_BLANK
        val status = json.integer("status")
        refuseUnless(status == null || status in LOWEST_STATUS..HIGHEST_STATUS)
        val subproblems = when (isNested) {
            true -> emptyList()
            false -> json.items(name = "subproblems", maximum = limits.maximumEntries).orEmpty()
        }
        return AcmeProblem(
            type = type,
            kind = AcmeProblemType.of(type),
            title = json.text("title"),
            detail = json.text("detail"),
            status = status?.toInt(),
            instance = json.text("instance"),
            identifier = json.member("identifier")?.let { found -> identifier(found) },
            subproblems = subproblems.map { item ->
                problem(json = item.asObject(), retryAfter = null, isNested = true)
            },
            retryAfter = retryAfter,
        )
    }

    fun renewal(json: JsonValue.Object, certificateId: String, retryAfter: Duration?): RenewalInfo {
        val window = required(json.member("suggestedWindow"))
        val start = time(window.requiredText("start"))
        val end = time(window.requiredText("end"))
        refuseUnless(end > start)
        return RenewalInfo(
            certificateId = certificateId,
            start = start,
            end = end,
            explanation = json.optionalUrl("explanationURL"),
            retryAfter = retryAfter,
        )
    }

    fun chain(body: ByteString, links: List<Link>): CertificateChain {
        val text = Utf8.decode(body)
        val blocks = Pem.decode(text).getOrNull() ?: refuse(AcmeError.Malformed)
        refuseUnless(condition = blocks.size <= limits.maximumCertificates, error = AcmeError.LimitExceeded)
        refuseUnless(blocks.isNotEmpty() && blocks.all { block -> block.label == CERTIFICATE_LABEL })
        val chain = blocks.map { block -> certificateOf(block.bytes) }
        val alternates = links.filter { link -> ALTERNATE in link.relations }
        return CertificateChain(certificates = chain, alternates = alternates.map { link -> url(link.target) })
    }

    fun time(text: String): Instant {
        refuseUnless(text.length <= MAXIMUM_TIME_LENGTH)
        return Instant.parse(text)
    }

    private fun certificateOf(bytes: ByteString): Certificate =
        certificates.decode(bytes).getOrNull() ?: refuse(AcmeError.Malformed)

    private fun JsonValue.Object.requiredUrl(name: String): String = url(requiredText(name))

    private fun JsonValue.Object.optionalUrl(name: String): String? = text(name)?.let { found -> url(found) }

    private fun JsonValue.Object.optionalTime(name: String): Instant? = text(name)?.let { found -> time(found) }

    private fun status(json: JsonValue.Object, allowed: Set<AcmeStatus>): AcmeStatus {
        val status = AcmeStatus.of(json.requiredText("status"))
        return required(status.takeIf { found -> found in allowed })
    }

    private fun <T : Any> required(value: T?): T = value ?: refuse(AcmeError.Malformed)

    private companion object {
        val ACCOUNT_STATUSES: Set<AcmeStatus> = setOf(AcmeStatus.Valid, AcmeStatus.Deactivated, AcmeStatus.Revoked)
        val ORDER_STATUSES: Set<AcmeStatus> = setOf(
            AcmeStatus.Pending,
            AcmeStatus.Ready,
            AcmeStatus.Processing,
            AcmeStatus.Valid,
            AcmeStatus.Invalid,
        )
        val AUTHORIZATION_STATUSES: Set<AcmeStatus> = setOf(
            AcmeStatus.Pending,
            AcmeStatus.Valid,
            AcmeStatus.Invalid,
            AcmeStatus.Deactivated,
            AcmeStatus.Expired,
            AcmeStatus.Revoked,
        )
        val CHALLENGE_STATUSES: Set<AcmeStatus> =
            setOf(AcmeStatus.Pending, AcmeStatus.Processing, AcmeStatus.Valid, AcmeStatus.Invalid)
    }
}
