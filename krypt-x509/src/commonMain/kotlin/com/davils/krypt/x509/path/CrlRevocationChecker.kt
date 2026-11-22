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

import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.crl.IssuingDistributionPoint
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.crl.RevocationLists
import com.davils.krypt.x509.extension.KeyUsage
import kotlin.time.Instant

/**
 * Checks revocation with full revocation lists from [source].
 *
 * A list counts only when it names the issuer of the certificate, is signed by the key that signed the certificate,
 * by an issuer whose key usage allows it, is fresh at the time of validation and covers the certificate. The newest
 * such list decides: a certificate on it is revoked, one that is not is good, unless the list covers only some
 * reasons. Without such a list the status is unknown. Delta lists and indirect lists are not used.
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
     * Returns the status of [certificate] by the newest fitting list.
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
        val fitting = source.revocationLists(certificate).filter { list ->
            isFitting(
                list,
                certificate,
                at,
            ) &&
                isListIssuer
        }
        val authentic = fitting.filter { list -> lists.verifySignature(list, issuerKey).isValid }
        val newest = authentic.maxByOrNull { list -> list.thisUpdate } ?: return RevocationStatus.Unknown
        val entry = newest.find(certificate.serialNumber)
        val isRevoked = entry != null && entry.reason != RevocationReason.RemoveFromCrl
        val isComplete = newest.issuingDistributionPoint?.onlySomeReasons == null
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

    private fun isFitting(list: RevocationList, certificate: Certificate, at: Instant): Boolean {
        val nextUpdate = list.nextUpdate
        val isFresh = nextUpdate != null && at >= list.thisUpdate && at <= nextUpdate
        val point = list.issuingDistributionPoint
        val isCovered = point?.let { scope -> isCovered(scope, certificate) } != false
        return list.issuer == certificate.issuer && !list.isDelta && isFresh && isCovered
    }

    private fun isCovered(point: IssuingDistributionPoint, certificate: Certificate): Boolean {
        val isCaMismatch = point.isCaOnly && !certificate.isCa
        val isUserMismatch = point.isUserOnly && certificate.isCa
        return !point.isIndirect && !isCaMismatch && !isUserMismatch
    }
}
