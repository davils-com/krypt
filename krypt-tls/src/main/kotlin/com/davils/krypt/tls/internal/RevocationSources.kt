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

package com.davils.krypt.tls.internal

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.ocsp.CertificateStatus
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.ocsp.OcspParameters
import com.davils.krypt.ocsp.OcspResponseSource
import com.davils.krypt.ocsp.SingleResponse
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.crl.RevocationLists
import com.davils.krypt.x509.path.CrlRevocationChecker
import com.davils.krypt.x509.path.RevocationListSource
import com.davils.krypt.x509.path.RevocationStatus
import com.davils.krypt.x509.path.TrustAnchor
import kotlin.time.Instant

internal class RevocationSources(
    private val ocsp: Ocsp,
    private val responses: OcspResponseSource?,
    private val lists: RevocationLists,
    private val listSource: RevocationListSource?,
) {
    suspend fun decide(
        certificate: Certificate,
        issuer: Certificate?,
        responder: OcspIssuer,
        anchor: TrustAnchor,
        at: Instant,
    ): RevocationDecision {
        val answered = fetched(certificate = certificate, issuer = responder, at = at)
        return answered ?: listed(certificate = certificate, issuer = issuer, anchor = anchor, at = at) ?: UNKNOWN
    }

    private suspend fun fetched(certificate: Certificate, issuer: OcspIssuer, at: Instant): RevocationDecision? {
        val source = responses ?: return null
        val certId = ocsp.certId(certificate = certificate, issuer = issuer)
        val request = ocsp.request(certIds = listOf(certId), nonceBytes = null)
        val encoded = source.response(request, certificate, issuer)
        val response = encoded?.let { bytes -> ocsp.decodeResponse(bytes).getOrNull() }
        val single = response?.let { found ->
            ocsp.verify(
                response = found,
                certificate = certificate,
                issuer = issuer,
                request = request,
                parameters = OcspParameters(at = at),
            )
        }
        return single?.getOrNull()?.let { verified -> decisionOf(verified) }
    }

    private suspend fun listed(
        certificate: Certificate,
        issuer: Certificate?,
        anchor: TrustAnchor,
        at: Instant,
    ): RevocationDecision? {
        val source = listSource ?: return null
        val seen = mutableListOf<RevocationList>()
        val recording = RevocationListSource { subject ->
            val returned = source.revocationLists(subject)
            seen += returned
            returned
        }
        val checker = CrlRevocationChecker(lists, recording)
        val status = checker.check(certificate = certificate, issuer = issuer, anchor = anchor, at = at)
        val updates = seen.mapNotNull { list -> list.nextUpdate }
        val horizon = updates.filter { update -> update > at }.minOrNull()
        val decision = RevocationDecision(status = status, nextUpdate = horizon)
        return decision.takeUnless { status == RevocationStatus.Unknown }
    }

    companion object {
        val UNKNOWN: RevocationDecision = RevocationDecision(status = RevocationStatus.Unknown, nextUpdate = null)

        fun decisionOf(single: SingleResponse): RevocationDecision? {
            val status = when (single.status) {
                CertificateStatus.Good -> RevocationStatus.Good
                is CertificateStatus.Revoked -> RevocationStatus.Revoked
                CertificateStatus.Unknown -> null
            }
            return status?.let { found -> RevocationDecision(status = found, nextUpdate = single.nextUpdate) }
        }
    }
}
