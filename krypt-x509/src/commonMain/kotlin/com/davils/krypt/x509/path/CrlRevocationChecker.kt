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

package com.davils.krypt.x509.path

import com.davils.kore.core.failure.attempted
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.crl.IssuingDistributionPoint
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.crl.RevocationLists
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.GeneralName
import kotlin.time.Instant

/**
 * Checks revocation with full revocation lists from [source].
 *
 * A list applies to a certificate only when it names the issuer of the certificate, is signed by the key that signed
 * the certificate, by an issuer whose key usage allows it, is fresh at the time of validation, has no critical
 * extension krypt does not know (in the list or in an entry), and its issuing distribution point covers the
 * certificate by RFC 5280, section 6.3.3: if it names a distribution point, one of its names must equal a full name or
 * the list issuer of a distribution point of the certificate; a list of end entities only does not cover an
 * authority, a list of authorities only does not cover an end entity; and an indirect list is not used.
 *
 * Every applicable list counts. A certificate on any of them is revoked, whatever the others say. Otherwise it is good
 * only if the applicable lists together cover every reason, so a list of some reasons alone leaves the status
 * unknown; without an applicable list the status is unknown. Delta lists are not used.
 *
 * The [source] is foreign code: a failure it throws counts as no list, and only the cancellation of the calling
 * coroutine passes through.
 *
 * @param lists the revocation lists and their primitives.
 * @param source where the lists come from.
 * @constructor Checks with lists of [source].
 * @since 1.0.0
 */
public class CrlRevocationChecker(
    private val lists: RevocationLists,
    private val source: RevocationListSource,
) : RevocationChecker {
    /**
     * Returns the status of [certificate] by the applicable lists.
     *
     * @param certificate the certificate.
     * @param issuer the certificate of its issuer, or null for an anchor.
     * @param anchor the anchor of the path.
     * @param at the time of validation.
     * @return the status.
     * @since 1.0.0
     */
    override suspend fun check(
        certificate: Certificate,
        issuer: Certificate?,
        anchor: TrustAnchor,
        at: Instant,
    ): RevocationStatus {
        val issuerKey = issuer?.publicKey ?: anchor.publicKey
        val isListIssuer = issuer?.extensions?.keyUsage?.let { usages -> KeyUsage.CrlSign in usages } != false
        val fetched = attempted { source.revocationLists(certificate) }
        val offered = fetched.getOrNull().orEmpty()
        val fitting = offered.filter { list ->
            isListIssuer &&
                isFitting(
                    list = list,
                    certificate = certificate,
                    at = at,
                )
        }
        val authentic = fitting.filter { list -> lists.verifySignature(list, issuerKey).isValid }
        val isRevoked = authentic.any { list -> isRevokedOn(list, certificate) }
        val covered = authentic.flatMap { list -> list.issuingDistributionPoint?.onlySomeReasons ?: ALL_REASONS }
        val isComplete = covered.containsAll(ALL_REASONS)
        val status = listOf(RevocationStatus.Unknown, RevocationStatus.Good)[isComplete.compareTo(false)]
        return RevocationStatus.Revoked.takeIf { isRevoked } ?: status
    }

    /**
     * Shows the source.
     *
     * @return the checker as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CrlRevocationChecker($source)"

    private fun isRevokedOn(list: RevocationList, certificate: Certificate): Boolean {
        val entry = list.find(certificate.serialNumber)
        return entry != null && entry.reason != RevocationReason.RemoveFromCrl
    }

    private fun isFitting(list: RevocationList, certificate: Certificate, at: Instant): Boolean {
        val nextUpdate = list.nextUpdate
        val isFresh = nextUpdate != null && at >= list.thisUpdate && at <= nextUpdate
        val point = list.issuingDistributionPoint
        val isCovered = point == null || isCovered(point, certificate)
        val isUsable = !list.isDelta && list.unknownCritical.isEmpty()
        return list.issuer == certificate.issuer && isUsable && isFresh && isCovered
    }

    private fun isCovered(point: IssuingDistributionPoint, certificate: Certificate): Boolean {
        val isCaMismatch = point.isCaOnly && !certificate.isCa
        val isUserMismatch = point.isUserOnly && certificate.isCa
        val isScopeMatching = !point.isIndirect && !isCaMismatch && !isUserMismatch
        return isScopeMatching && isPointMatching(point.names, certificate)
    }

    private fun isPointMatching(names: List<GeneralName>, certificate: Certificate): Boolean {
        val points = certificate.extensions.crlDistributionPoints
        val offered = points.flatMap { point -> point.names.ifEmpty { point.crlIssuer } }
        return names.isEmpty() || offered.any { name -> name in names }
    }

    private companion object {
        val ALL_REASONS: Set<RevocationReason> = RevocationReason.entries
            .filter { reason -> reason.bit != null }
            .toSet()
    }
}
