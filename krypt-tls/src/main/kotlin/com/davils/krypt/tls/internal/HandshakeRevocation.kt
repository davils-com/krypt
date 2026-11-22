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
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.ocsp.OcspParameters
import com.davils.krypt.ocsp.SingleResponse
import com.davils.krypt.tls.trust.RevocationCache
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.RevocationChecker
import com.davils.krypt.x509.path.RevocationStatus
import com.davils.krypt.x509.path.TrustAnchor
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal class HandshakeRevocation(
    private val ocsp: Ocsp,
    private val chain: List<Certificate>,
    private val staples: List<ByteString>,
    private val cache: RevocationCache?,
    private val sources: RevocationSources,
) : RevocationChecker {
    var leafStaple: SingleResponse? = null
        private set

    override suspend fun check(
        certificate: Certificate,
        issuer: Certificate?,
        anchor: TrustAnchor,
        at: Instant,
    ): RevocationStatus {
        val responder = issuer?.let { found -> OcspIssuer.of(found) } ?: OcspIssuer.of(anchor)
        val stapled = stapled(certificate = certificate, issuer = responder, at = at)
        val cached = cache?.status(certificate, at)
        if (stapled == null && cached != null) return cached
        val decision = stapled ?: sources.decide(
            certificate = certificate,
            issuer = issuer,
            responder = responder,
            anchor = anchor,
            at = at,
        )
        cache?.put(certificate = certificate, status = decision.status, at = at, nextUpdate = decision.nextUpdate)
        return decision.status
    }

    private suspend fun stapled(certificate: Certificate, issuer: OcspIssuer, at: Instant): RevocationDecision? {
        val staple = staples.getOrNull(chain.indexOf(certificate))?.takeIf { bytes -> bytes.size > 0 } ?: return null
        val single = verified(staple = staple, certificate = certificate, issuer = issuer, at = at)
        if (single != null && certificate == chain.first()) leafStaple = single
        return single?.let { found -> RevocationSources.decisionOf(found) }
    }

    private suspend fun verified(
        staple: ByteString,
        certificate: Certificate,
        issuer: OcspIssuer,
        at: Instant,
    ): SingleResponse? {
        val response = ocsp.decodeResponse(staple).getOrNull() ?: return null
        val verification = ocsp.verify(
            response = response,
            certificate = certificate,
            issuer = issuer,
            parameters = OcspParameters(at = at),
        )
        return verification.getOrNull()
    }
}
