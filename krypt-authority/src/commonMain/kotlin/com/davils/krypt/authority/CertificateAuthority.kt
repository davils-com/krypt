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

package com.davils.krypt.authority

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.authority.internal.KeyIds
import com.davils.krypt.authority.internal.ProfileExtensions
import com.davils.krypt.authority.internal.RequestChecks
import com.davils.krypt.authority.internal.Serials
import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.authority.store.AuthorityRepository
import com.davils.krypt.authority.store.Revocation
import com.davils.krypt.core.audit.AuditAction
import com.davils.krypt.core.telemetry.AuditTrail
import com.davils.krypt.ocsp.CertificateStatus
import com.davils.krypt.ocsp.OcspStatusSource
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.crl.RevocationLists
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.request.CertificationRequest
import com.davils.krypt.x509.request.CertificationRequests
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

private const val SERIAL_ATTEMPTS: Int = 3
private const val DEFAULT_LIST_DAYS: Int = 7
private const val DEFAULT_OVERLAP_MINUTES: Int = 5
private const val REPOSITORY_FAILED: String = "The repository of the authority failed"

private fun nowOf(crypto: Crypto): Instant {
    val now = crypto.environment.clock.now()
    return Instant.fromEpochSeconds(now.epochSeconds)
}

/**
 * A certificate authority without state of its own: it issues and revokes certificates, writes revocation lists and
 * answers the status questions of an OCSP responder, and keeps everything in the [repository] of the application.
 *
 * The key of the authority stays behind [signer], which may be an HSM or a key management service; krypt never
 * sees it. Every certificate gets a fresh 159-bit random serial number, key identifiers of RFC 7093, the profile's
 * usages and the policy's revocation pointers, and is recorded before it is returned. Issuance and revocation are
 * recorded in the audit trail of the environment; when the audit is required and fails, the operation throws
 * [com.davils.krypt.core.audit.AuditRefusedException] after the repository changed.
 *
 * The [repository] is foreign code. Every call of it runs contained: a failure of it makes [issue], [enroll] and
 * [revoke] answer [IssuanceFailure.RepositoryUnavailable] or [RevocationFailure.RepositoryUnavailable], and makes the
 * revocation lists throw an [IllegalStateException]; only the cancellation of the calling coroutine passes through as
 * it is. The [statusSource] lets a failure pass to the [com.davils.krypt.ocsp.OcspResponder], which answers it with
 * an internal error.
 *
 * The authority holds no mutable state and is safe to share between coroutines, as far as the repository is.
 *
 * @property crypto the primitives.
 * @property certificate the certificate of the authority.
 * @property signer the signer of the authority's key.
 * @property repository where issued certificates and revocations are kept.
 * @property policy what the authority may issue.
 * @constructor Opens the authority.
 * @throws IllegalArgumentException if [certificate] is no authority, may not sign certificates or does not hold the
 *   key of [signer].
 * @since 1.0.0
 */
public class CertificateAuthority(
    public val crypto: Crypto,
    public val certificate: Certificate,
    public val signer: Signer,
    public val repository: AuthorityRepository,
    public val policy: IssuancePolicy = IssuancePolicy.Default,
) {
    private val certificates: Certificates = Certificates(crypto)

    private val revocationLists: RevocationLists = RevocationLists(crypto)

    private val checks: RequestChecks = RequestChecks(certificate, policy)

    private val trail: AuditTrail = AuditTrail(crypto.environment)

    /**
     * The status of the certificates of this authority for an [com.davils.krypt.ocsp.OcspResponder]: good, revoked,
     * or unknown for a serial number the authority did not issue.
     *
     * @since 1.0.0
     */
    public val statusSource: OcspStatusSource = OcspStatusSource { serialNumber -> statusOf(serialNumber) }

    init {
        require(certificate.isCa) { "An authority has an authority certificate" }
        val usages = certificate.extensions.keyUsage
        require(usages == null || KeyUsage.KeyCertSign in usages) { "An authority may sign certificates" }
        require(certificate.publicKey == signer.publicKey) { "The signer holds the key of the authority" }
    }

    /**
     * Issues a certificate.
     *
     * The request is checked against its profile and the policy first: the key family, the alternative names and the
     * subject as [IssuancePolicy] describes, the validity, which must end before the authority's, and the path length
     * of the authority. The validity starts [IssuancePolicy.backdate] before now.
     *
     * @param request what the certificate shall say.
     * @return the certificate, recorded in the repository, or why it was refused.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if the required audit failed.
     * @since 1.0.0
     */
    public suspend fun issue(request: IssuanceRequest): Outcome<Certificate, IssuanceFailure> {
        val now = nowOf(crypto)
        val failure = checks.failureOf(request, now)
        if (failure != null) return Outcome.Failure(failure)
        val ids = KeyIds(subject = certificates.keyIdentifier(request.publicKey), authority = authorityKeyId())
        val issued = (1..SERIAL_ATTEMPTS).firstNotNullOfOrNull { issueOnce(request = request, ids = ids, at = now) }
        return issued ?: Outcome.Failure(IssuanceFailure.SerialConflict)
    }

    /**
     * Issues a certificate for a certification request (PKCS #10) of a subject.
     *
     * The signature of the request proves that the subject holds the key. The subject and the subject alternative
     * names come from the request and are checked like those of [issue], by the names of the [policy] and the rules
     * of the subject that [IssuancePolicy] describes; every other requested extension is ignored, the profile
     * decides.
     *
     * @param request the certification request, possibly from an attacker.
     * @param profile what the certificate is for.
     * @param validity how long the certificate is valid, or null for the longest allowed.
     * @param nameConstraints the constraints of an authority certificate, or null.
     * @return the certificate, or why it was refused.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if the required audit failed.
     * @since 1.0.0
     */
    public suspend fun enroll(
        request: CertificationRequest,
        profile: CertificateProfile,
        validity: Duration? = null,
        nameConstraints: NameConstraints? = null,
    ): Outcome<Certificate, IssuanceFailure> {
        val publicKey = request.publicKey ?: return Outcome.Failure(IssuanceFailure.KeyNotPermitted)
        val isSigned = CertificationRequests(crypto).verify(request).isValid
        val issuance = IssuanceRequest(
            subject = request.subject,
            publicKey = publicKey,
            profile = profile,
            names = request.requestedExtensions.subjectAlternativeNames,
            validity = validity,
            nameConstraints = nameConstraints,
        )
        return when (isSigned) {
            true -> issue(issuance)
            false -> Outcome.Failure(IssuanceFailure.InvalidRequest)
        }
    }

    /**
     * Revokes a certificate this authority issued; a revocation is final.
     *
     * @param serialNumber the serial number of the certificate.
     * @param reason why, or null; [RevocationReason.Unspecified] is written as no reason, as RFC 5280 asks.
     * @param invalidAt since when the key is known or suspected to be compromised, or null.
     * @return the revocation, or why it was refused.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if the required audit failed.
     * @since 1.0.0
     */
    public suspend fun revoke(
        serialNumber: DerInteger,
        reason: RevocationReason? = null,
        invalidAt: Instant? = null,
    ): Outcome<Revocation, RevocationFailure> {
        val revocation = Revocation(
            serialNumber = serialNumber,
            revokedAt = nowOf(crypto),
            reason = reason?.takeUnless { given -> given == RevocationReason.Unspecified },
            invalidAt = invalidAt,
        )
        val failure = RevocationFailure.ReasonNotPermitted.takeIf { reason in HOLDS }
            ?: revocationFailureOf(revocation)
        if (failure != null) return Outcome.Failure(failure)
        return recorded(revocation)
    }

    /**
     * Writes a full revocation list with every revocation and the next number of the repository.
     *
     * The time of the list is taken before the revocations are read, so a revocation the repository records later is
     * dated no earlier than [DEFAULT_OVERLAP] before it and reaches the next delta list.
     *
     * @param validity how long until the next list; seven days by default.
     * @return the list.
     * @throws IllegalArgumentException if [validity] is not positive.
     * @throws IllegalStateException if the list holds more entries than the limits of krypt-x509 allow, or the
     *   repository failed.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if the required audit failed.
     * @since 1.0.0
     */
    public suspend fun revocationList(validity: Duration = DEFAULT_LIST_DAYS.days): RevocationList {
        require(validity.isPositive()) { "A revocation list is valid for a positive time" }
        val now = nowOf(crypto)
        val revocations = stored { repository.revocations() }
        return issueList(revocations = revocations, base = null, validity = validity, now = now)
    }

    /**
     * Writes a delta revocation list with the revocations since [base], a full list of this authority.
     *
     * The delta holds every revocation dated at or after the time of [base] minus [overlap]. A revocation is dated
     * before the repository records it, so one dated shortly before [base] may be missing from it; the overlap covers
     * it, and must be at least the longest time between taking the date of a revocation and the repository
     * recording it. A revocation that is in [base] as well is listed again, which RFC 5280 allows.
     *
     * @param base the full list the delta builds on.
     * @param validity how long until the next list; seven days by default.
     * @param overlap how far before the time of [base] the delta reaches back; [DEFAULT_OVERLAP] by default.
     * @return the list.
     * @throws IllegalArgumentException if [base] is no full list of this authority, [validity] is not positive or
     *   [overlap] is negative.
     * @throws IllegalStateException if the repository failed.
     * @throws com.davils.krypt.core.audit.AuditRefusedException if the required audit failed.
     * @since 1.0.0
     */
    public suspend fun deltaRevocationList(
        base: RevocationList,
        validity: Duration = DEFAULT_LIST_DAYS.days,
        overlap: Duration = DEFAULT_OVERLAP,
    ): RevocationList {
        val baseNumber = base.number
        val baseAuthority = base.extensions.authorityKeyIdentifier?.keyIdentifier
        val isOwn = base.issuer == certificate.subject && baseAuthority == authorityKeyId()
        require(isOwn && !base.isDelta && baseNumber != null) { "A delta builds on a full list of this authority" }
        require(!overlap.isNegative()) { "The overlap of a delta is not negative" }
        require(validity.isPositive()) { "A revocation list is valid for a positive time" }
        val now = nowOf(crypto)
        val start = base.thisUpdate - overlap
        val revocations = stored { repository.revocations() }
        val since = revocations.filter { revocation -> revocation.revokedAt >= start }
        return issueList(revocations = since, base = baseNumber, validity = validity, now = now)
    }

    /**
     * Shows the subject of the authority.
     *
     * @return the authority as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CertificateAuthority(${certificate.subject})"

    private suspend fun issueOnce(
        request: IssuanceRequest,
        ids: KeyIds,
        at: Instant,
    ): Outcome<Certificate, IssuanceFailure>? {
        val notBefore = at - policy.backdate
        val issued = certificates.issue(signer) {
            serialNumber = Serials.next(crypto)
            subject = request.subject
            issuer = certificate.subject
            publicKey = request.publicKey
            this.notBefore = notBefore
            notAfter = at + checks.validityOf(request)
            extensions { ProfileExtensions(request, policy).write(this, ids) }
        }
        val recording = attempted { repository.record(issued) }
        val isRecorded = recording.getOrNull() ?: return Outcome.Failure(IssuanceFailure.RepositoryUnavailable)
        if (isRecorded) {
            val attributes = mapOf(PROFILE to request.profile.name, SUBJECT to issued.subject.toString())
            trail.require(action = ISSUE, subject = issued.serialNumber.toString(), attributes = attributes)
        }
        return Outcome.Success(issued).takeIf { isRecorded }
    }

    private suspend fun revocationFailureOf(revocation: Revocation): RevocationFailure? {
        val found = attempted { issuedHere(revocation.serialNumber) }
        val isIssued = found.getOrNull() != null
        val isRevocable = found.isSuccess && isIssued
        val revoking = attempted { revocation.takeIf { isRevocable }?.let { given -> repository.revoke(given) } }
        val isRevoked = revoking.getOrNull()
        val isAvailable = found.isSuccess && revoking.isSuccess
        val failures = listOf(
            RevocationFailure.RepositoryUnavailable.takeUnless { isAvailable },
            RevocationFailure.UnknownCertificate.takeUnless { isIssued },
            RevocationFailure.AlreadyRevoked.takeIf { isRevoked == false },
        )
        return failures.firstOrNull { failure -> failure != null }
    }

    private suspend fun <T> stored(block: suspend () -> T): T {
        val result = attempted { block() }
        return result.getOrElse { failure -> throw IllegalStateException(REPOSITORY_FAILED, failure) }
    }

    private suspend fun recorded(revocation: Revocation): Outcome<Revocation, RevocationFailure> {
        val reason: Any = revocation.reason ?: NONE
        val attributes = mapOf(REASON to reason.toString())
        trail.require(action = REVOKE, subject = revocation.serialNumber.toString(), attributes = attributes)
        return Outcome.Success(revocation)
    }

    private suspend fun issueList(
        revocations: List<Revocation>,
        base: DerInteger?,
        validity: Duration,
        now: Instant,
    ): RevocationList {
        val number = DerInteger.of(stored { repository.nextCrlNumber() })
        val authorityId = authorityKeyId()
        val list = revocationLists.issue(signer) {
            issuer = certificate.subject
            thisUpdate = now
            nextUpdate = now + validity
            this.number = number
            deltaOf = base
            revocations.forEach { revocation ->
                revoke(
                    serialNumber = revocation.serialNumber,
                    revokedAt = revocation.revokedAt,
                    reason = revocation.reason,
                    invalidAt = revocation.invalidAt,
                )
            }
            extensions { authorityKeyIdentifier(authorityId) }
        }
        val attributes = mapOf(ENTRIES to revocations.size.toString())
        trail.require(action = PUBLISH, subject = number.toString(), attributes = attributes)
        return list
    }

    private suspend fun statusOf(serialNumber: DerInteger): CertificateStatus? {
        val issued = issuedHere(serialNumber)
        val revocation = issued?.let { repository.revocation(serialNumber) }
        val revoked = revocation?.let { found -> CertificateStatus.Revoked(found.revokedAt, found.reason) }
        return revoked ?: CertificateStatus.Good.takeIf { issued != null }
    }

    private suspend fun issuedHere(serialNumber: DerInteger): Certificate? {
        val authorityId = authorityKeyId()
        return repository.find(serialNumber)?.takeIf { found ->
            val identifier = found.extensions.authorityKeyIdentifier?.keyIdentifier
            found.issuer == certificate.subject && identifier == authorityId
        }
    }

    private suspend fun authorityKeyId(): ByteString = certificate.extensions.subjectKeyIdentifier
        ?: certificates.keyIdentifier(signer.publicKey)

    /**
     * Creates the self-signed certificate of a root authority.
     *
     * @since 1.0.0
     */
    public companion object {
        private val ISSUE: AuditAction = AuditAction("authority.issue")
        private val REVOKE: AuditAction = AuditAction("authority.revoke")
        private val PUBLISH: AuditAction = AuditAction("authority.publish-crl")
        private val HOLDS: Set<RevocationReason?> =
            setOf(RevocationReason.CertificateHold, RevocationReason.RemoveFromCrl)
        private const val PROFILE: String = "profile"
        private const val SUBJECT: String = "subject"
        private const val REASON: String = "reason"
        private const val ENTRIES: String = "entries"
        private const val NONE: String = "none"

        /**
         * How far a delta list reaches back before the time of its base by default: five minutes.
         *
         * @since 1.0.0
         */
        public val DEFAULT_OVERLAP: Duration = DEFAULT_OVERLAP_MINUTES.minutes

        /**
         * Creates the self-signed certificate of a root authority, valid from now.
         *
         * A root is created once, kept offline and signs the requests of its intermediates; open it with the
         * constructor to issue.
         *
         * @param crypto the primitives.
         * @param signer the signer of the root's key.
         * @param subject the name of the root.
         * @param validity how long the root is valid.
         * @param pathLength how many authorities may follow it, or null for no limit.
         * @return the certificate.
         * @throws IllegalArgumentException if [validity] is not positive or [pathLength] is negative.
         * @since 1.0.0
         */
        public suspend fun createRoot(
            crypto: Crypto,
            signer: Signer,
            subject: DistinguishedName,
            validity: Duration,
            pathLength: Int? = null,
        ): Certificate {
            require(validity.isPositive()) { "A root is valid for a positive time" }
            require(pathLength == null || pathLength >= 0) { "A path length is not negative" }
            val certificates = Certificates(crypto)
            val keyId = certificates.keyIdentifier(signer.publicKey)
            val now = nowOf(crypto)
            return certificates.issue(signer) {
                serialNumber = Serials.next(crypto)
                this.subject = subject
                publicKey = signer.publicKey
                notBefore = now
                notAfter = now + validity
                extensions {
                    basicConstraints(isCa = true, pathLength = pathLength)
                    keyUsage(setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign, KeyUsage.DigitalSignature))
                    subjectKeyIdentifier(keyId)
                }
            }
        }
    }
}
