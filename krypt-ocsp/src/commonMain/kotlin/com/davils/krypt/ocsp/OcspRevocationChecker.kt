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

package com.davils.krypt.ocsp

import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.RevocationChecker
import com.davils.krypt.x509.path.RevocationStatus
import com.davils.krypt.x509.path.TrustAnchor
import kotlin.time.Instant

/**
 * Checks revocation with OCSP responses from [source], for the path validation of RFC 5280.
 *
 * For every certificate the checker builds a request and asks [source]. A response counts only when
 * [Ocsp.verify] accepts it at the time of validation; good and revoked answers decide, while an unknown answer, no
 * response or one that fails verification leave the status unknown. By default the request carries no nonce, so
 * cached and stapled responses verify.
 *
 * The [source] is foreign code: a failure it throws counts as no response, so the status is unknown, and only the
 * cancellation of the calling coroutine passes through. The TLS feature extension (must-staple) of a certificate is
 * not enforced here, because only the TLS layer knows whether a response was stapled; krypt-tls enforces it.
 *
 * @param ocsp the requests and their verification.
 * @param source where the responses come from.
 * @param parameters the parameters of verification; their time is replaced by the time of validation.
 * @param hashAlgorithm the digest of the identifiers in the requests.
 * @param nonceBytes the size of the nonce of each request, or null for none.
 * @constructor Checks with responses of [source].
 * @throws IllegalArgumentException if [nonceBytes] is neither null nor [Ocsp.MINIMUM_NONCE_SIZE] to
 *   [Ocsp.MAXIMUM_NONCE_SIZE].
 * @since 1.0.0
 */
public class OcspRevocationChecker(
    private val ocsp: Ocsp,
    private val source: OcspResponseSource,
    private val parameters: OcspParameters = OcspParameters(),
    private val hashAlgorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
    private val nonceBytes: Int? = null,
) : RevocationChecker {
    init {
        require(nonceBytes == null || nonceBytes in Ocsp.MINIMUM_NONCE_SIZE..Ocsp.MAXIMUM_NONCE_SIZE) {
            "A nonce of a request has ${Ocsp.MINIMUM_NONCE_SIZE} to ${Ocsp.MAXIMUM_NONCE_SIZE} bytes"
        }
    }

    /**
     * Returns the status of [certificate] by the response of the source.
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
        val responseIssuer = issuerOf(issuer, anchor) ?: return RevocationStatus.Unknown
        val certId = ocsp.certId(certificate = certificate, issuer = responseIssuer, algorithm = hashAlgorithm)
        val request = ocsp.request(listOf(certId), nonceBytes)
        val fetched = attempted { source.response(request, certificate, responseIssuer) }
        val encoded = fetched.getOrNull()
        val response = encoded?.let { bytes -> ocsp.decodeResponse(bytes).getOrNull() }
        val verification = OcspParameters(
            at = at,
            skew = parameters.skew,
            maximumAge = parameters.maximumAge,
            isNonceRequired = parameters.isNonceRequired,
            isNoCheckRequired = parameters.isNoCheckRequired,
        )
        val answer = response?.let { found ->
            ocsp.verify(
                response = found,
                certificate = certificate,
                issuer = responseIssuer,
                request = request,
                parameters = verification,
            )
        }
        return statusOf(answer?.getOrNull()?.status)
    }

    /**
     * Shows the source.
     *
     * @return the checker as text.
     * @since 1.0.0
     */
    override fun toString(): String = "OcspRevocationChecker($source)"

    private fun issuerOf(issuer: Certificate?, anchor: TrustAnchor): OcspIssuer? {
        if (issuer == null) return OcspIssuer.of(anchor)
        return issuer.publicKey?.let { key -> OcspIssuer(issuer.subject, key) }
    }

    private fun statusOf(status: CertificateStatus?): RevocationStatus = when (status) {
        CertificateStatus.Good -> RevocationStatus.Good
        is CertificateStatus.Revoked -> RevocationStatus.Revoked
        CertificateStatus.Unknown, null -> RevocationStatus.Unknown
    }
}
