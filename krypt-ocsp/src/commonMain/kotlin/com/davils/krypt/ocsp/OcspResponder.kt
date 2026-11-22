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
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.ocsp.internal.CertIds
import com.davils.krypt.ocsp.internal.ResponseCodec
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

/**
 * The logic of an OCSP responder for the certificates of [issuer], by RFC 6960 and the profile of RFC 9919.
 *
 * The caller receives requests over HTTP, hands them over and returns the answer with the content type
 * [OcspEncodings.RESPONSE_MEDIA_TYPE]. Responses are signed by [signer], which may hold a key in an HSM: the key of
 * [issuer] itself, or the key of [responderCertificate], a delegated responder certificate that [issuer] issued with
 * id-kp-OCSPSigning. The responder names itself by the name of its certificate. Every answer is valid from the time
 * it is signed for [validity]; a nonce of the request is echoed. Answers about one certificate without a nonce are
 * kept in [cache] and served from it until they expire.
 *
 * The [source] is foreign code: if it throws, the request is answered with [OcspResponseStatus.InternalError],
 * which is neither signed nor cached, and only the cancellation of the calling coroutine passes through.
 *
 * @param ocsp the reading of requests and the identifiers of certificates.
 * @param issuer the issuer whose certificates the responder answers for.
 * @param signer the signer of the responses.
 * @param source where the status of a certificate comes from.
 * @param responderCertificate the certificate of [signer] if it is a delegated responder, or null if [signer] holds
 *   the key of [issuer].
 * @param validity how long an answer is valid.
 * @param cache the cache of signed answers, or null for none.
 * @constructor Answers for [issuer].
 * @throws IllegalArgumentException if [validity] is not positive or [responderCertificate] does not hold the key of
 *   [signer].
 * @since 1.0.0
 */
public class OcspResponder(
    private val ocsp: Ocsp,
    private val issuer: OcspIssuer,
    private val signer: Signer,
    private val source: OcspStatusSource,
    private val responderCertificate: Certificate? = null,
    private val validity: Duration = DEFAULT_VALIDITY_HOURS.hours,
    private val cache: OcspResponseCache? = null,
) {
    private val responderName: ByteString = listOfNotNull(responderCertificate?.subject, issuer.name).first().encoded

    init {
        require(validity.isPositive()) { "An answer is valid for a positive time" }
        require(responderCertificate == null || responderCertificate.publicKey == signer.publicKey) {
            "The responder certificate holds the key of the signer"
        }
    }

    /**
     * Answers the request in DER [request].
     *
     * A request that cannot be read is answered with [OcspResponseStatus.MalformedRequest].
     *
     * @param request the encoding of the request, possibly from an attacker.
     * @return the DER encoding of the response.
     * @since 1.0.0
     */
    public suspend fun respond(request: ByteString): ByteString {
        val outcome = ocsp.decodeRequest(request)
        val decoded = outcome.getOrNull() ?: return errorResponse(OcspResponseStatus.MalformedRequest)
        return respond(decoded)
    }

    /**
     * Answers [request].
     *
     * Every certificate of [issuer] is answered with the status from the source, or as unknown if the source does not
     * know it. A certificate of another issuer, or one identified with a digest the policy does not accept, is
     * answered as unknown. If the request names no certificate of [issuer], the answer is
     * [OcspResponseStatus.Unauthorized]; if the source fails, it is [OcspResponseStatus.InternalError].
     *
     * @param request the request.
     * @return the DER encoding of the response.
     * @since 1.0.0
     */
    public suspend fun respond(request: OcspRequest): ByteString {
        val isCacheable = request.nonce == null && request.certIds.size == 1
        val cached = cache?.takeIf { isCacheable }?.get(request.certIds.first(), now())
        val known = request.certIds.filter { certId -> isKnown(certId) }
        val answered = cached ?: known.takeIf { found -> found.isNotEmpty() }?.let { found -> answer(request, found) }
        return answered ?: errorResponse(OcspResponseStatus.Unauthorized)
    }

    /**
     * Signs an answer about the certificate with [serialNumber] ahead of time and keeps it in the cache, so that
     * the next request about it is served without signing.
     *
     * @param serialNumber the serial number of a certificate of [issuer].
     * @param algorithm the digest of its identifier, which clients must use to hit the cache.
     * @return the DER encoding of the response, or of an [OcspResponseStatus.InternalError] if the source failed.
     * @throws IllegalArgumentException if [algorithm] is neither SHA-1 nor SHA-2.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy does not accept [algorithm] for
     *   verification.
     * @since 1.0.0
     */
    public suspend fun presign(
        serialNumber: DerInteger,
        algorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
    ): ByteString {
        val certId = ocsp.certId(issuer = issuer, serialNumber = serialNumber, algorithm = algorithm)
        return answer(ocsp.request(listOf(certId), nonceBytes = null), listOf(certId))
    }

    /**
     * Signs [responses] into a successful response produced now.
     *
     * @param responses the answers, at least one.
     * @param nonce the nonce to echo, or null.
     * @return the DER encoding of the response.
     * @throws IllegalArgumentException if [responses] is empty.
     * @since 1.0.0
     */
    public suspend fun sign(responses: List<SingleResponse>, nonce: ByteString? = null): ByteString {
        require(responses.isNotEmpty()) { "A response answers about at least one certificate" }
        val tbs = ResponseCodec.encodeData(
            responderName = responderName,
            producedAt = now(),
            responses = responses,
            nonce = nonce,
        )
        return ResponseCodec.encodeResponse(
            tbs = tbs,
            algorithm = signer.algorithm,
            signature = signer.sign(tbs),
            certificates = listOfNotNull(responderCertificate),
        )
    }

    /**
     * Returns an unsigned response with the error [status].
     *
     * @param status the error.
     * @return the DER encoding of the response.
     * @throws IllegalArgumentException if [status] is [OcspResponseStatus.Successful].
     * @since 1.0.0
     */
    public fun errorResponse(status: OcspResponseStatus): ByteString {
        require(status != OcspResponseStatus.Successful) { "A successful response is signed" }
        return ResponseCodec.encodeError(status)
    }

    /**
     * Shows the issuer.
     *
     * @return the responder as text.
     * @since 1.0.0
     */
    override fun toString(): String = "OcspResponder($issuer)"

    private suspend fun isKnown(certId: CertId): Boolean {
        val isPermitted = CertIds.isPermitted(ocsp.crypto, certId.hashAlgorithm)
        val expected = certId.takeIf { isPermitted }?.let { found ->
            ocsp.certId(issuer = issuer, serialNumber = found.serialNumber, algorithm = found.hashAlgorithm)
        }
        return expected == certId
    }

    private suspend fun answer(request: OcspRequest, known: List<CertId>): ByteString {
        val thisUpdate = now()
        val nextUpdate = thisUpdate + validity
        val statuses = request.certIds.map { certId ->
            attempted { source.takeIf { certId in known }?.status(certId.serialNumber) }
        }
        if (statuses.any { status -> status.isFailure }) return errorResponse(OcspResponseStatus.InternalError)
        val responses = request.certIds.zip(statuses) { certId, status ->
            SingleResponse(
                certId = certId,
                status = status.getOrNull() ?: CertificateStatus.Unknown,
                thisUpdate = thisUpdate,
                nextUpdate = nextUpdate,
            )
        }
        val encoded = sign(responses, request.nonce)
        val isCacheable = request.nonce == null && responses.size == 1
        cache?.takeIf { isCacheable }?.put(request.certIds.first(), encoded, nextUpdate)
        return encoded
    }

    private fun now(): Instant {
        val clock = ocsp.crypto.environment.clock
        return Instant.fromEpochSeconds(clock.now().epochSeconds)
    }

    private companion object {
        const val DEFAULT_VALIDITY_HOURS: Int = 24
    }
}
