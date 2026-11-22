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

package com.davils.krypt.ocsp

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.ocsp.internal.CertIds
import com.davils.krypt.ocsp.internal.MAXIMUM_NONCE_BYTES
import com.davils.krypt.ocsp.internal.MINIMUM_NONCE_BYTES
import com.davils.krypt.ocsp.internal.RequestCodec
import com.davils.krypt.ocsp.internal.RequestCodec.readRequest
import com.davils.krypt.ocsp.internal.ResponseCodec.readResponse
import com.davils.krypt.ocsp.internal.ResponseVerifier
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString

/**
 * Builds and reads OCSP requests and reads and verifies OCSP responses by RFC 6960, with the nonce of RFC 9654.
 *
 * krypt sends nothing: the caller carries the encodings to the responder and back, by HTTP POST or GET as
 * [OcspEncodings] describes. The object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives and their policy.
 * @property limits the limits of reading.
 * @constructor Works with [crypto] within [limits].
 * @since 1.0.0
 */
public class Ocsp(public val crypto: Crypto, public val limits: OcspLimits = OcspLimits.Default) {
    private val certificates = Certificates(crypto)
    private val verifier = ResponseVerifier(crypto, certificates)
    private val derLimits = DerLimits(maximumBytes = limits.maximumBytes)

    /**
     * Returns the identifier of the certificate with [serialNumber] that [issuer] issued.
     *
     * SHA-256 is the default; SHA-384 and SHA-512 work as well. Older responders know only SHA-1,
     * which needs `@LegacyCryptography` and a policy that accepts SHA-1 for verification. The digests only identify
     * the certificate; they protect nothing.
     *
     * @param issuer the issuer.
     * @param serialNumber the serial number of the certificate.
     * @param algorithm the digest of the name and the key of [issuer].
     * @return the identifier.
     * @throws IllegalArgumentException if [algorithm] is neither SHA-1 nor SHA-2.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy does not accept [algorithm] for
     *   verification.
     * @since 1.0.0
     */
    public suspend fun certId(
        issuer: OcspIssuer,
        serialNumber: DerInteger,
        algorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
    ): CertId = CertIds.of(crypto = crypto, issuer = issuer, serialNumber = serialNumber, algorithm = algorithm)

    /**
     * Returns the identifier of [certificate], which [issuer] issued.
     *
     * @param certificate the certificate.
     * @param issuer its issuer.
     * @param algorithm the digest of the name and the key of [issuer].
     * @return the identifier.
     * @throws IllegalArgumentException if [algorithm] is neither SHA-1 nor SHA-2.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy does not accept [algorithm] for
     *   verification.
     * @since 1.0.0
     */
    public suspend fun certId(
        certificate: Certificate,
        issuer: OcspIssuer,
        algorithm: DigestAlgorithm = DigestAlgorithm.Sha256,
    ): CertId = certId(issuer = issuer, serialNumber = certificate.serialNumber, algorithm = algorithm)

    /**
     * Builds an unsigned request for [certIds] with a fresh nonce of [nonceBytes] random bytes from the environment.
     *
     * A nonce binds the response to the request and defeats replay, but responders that answer from a cache ignore
     * it, and a request with a nonce cannot be cached on the way.
     *
     * @param certIds the certificates, at least one and at most [OcspLimits.maximumEntries].
     * @param nonceBytes the size of the nonce, [MINIMUM_NONCE_SIZE] to [MAXIMUM_NONCE_SIZE] bytes, or null for no
     *   nonce.
     * @return the request.
     * @throws IllegalArgumentException if the number of certificates or the size of the nonce is out of range.
     * @since 1.0.0
     */
    public fun request(certIds: List<CertId>, nonceBytes: Int? = DEFAULT_NONCE_SIZE): OcspRequest {
        require(certIds.size in 1..limits.maximumEntries) {
            "A request names 1 to ${limits.maximumEntries} certificates"
        }
        require(nonceBytes == null || nonceBytes in MINIMUM_NONCE_BYTES..MAXIMUM_NONCE_BYTES) {
            "A nonce of a request has $MINIMUM_NONCE_BYTES to $MAXIMUM_NONCE_BYTES bytes"
        }
        val random = crypto.environment.random
        val nonce = nonceBytes?.let { count -> ByteString(random.bytes(count)) }
        return OcspRequest(certIds = certIds, nonce = nonce, encoded = RequestCodec.encode(certIds, nonce))
    }

    /**
     * Reads a request in DER, as a responder does.
     *
     * A signature of the request and the name of the requestor are skipped, not verified. A critical extension
     * other than the nonce, an empty nonce or one of more than [MAXIMUM_NONCE_SIZE] bytes and an explicit default
     * version are refused.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the request, or [OcspFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeRequest(encoded: ByteString): Outcome<OcspRequest, OcspFailure> {
        val request = Der.decodeOrNull(encoded, derLimits) { readRequest(encoded, limits) }
        val success = request?.let { found -> Outcome.Success(found) }
        return success ?: Outcome.Failure(OcspFailure.Malformed)
    }

    /**
     * Reads a response in DER.
     *
     * Only the basic response type is read. Certificates in the response are read with the limits of X.509. A
     * critical extension other than the nonce is refused.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the response, which is not verified yet, or [OcspFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeResponse(encoded: ByteString): Outcome<OcspResponse, OcspFailure> {
        val response = Der.decodeOrNull(encoded, derLimits) { readResponse(encoded, limits, certificates) }
        val success = response?.let { found -> Outcome.Success(found) }
        return success ?: Outcome.Failure(OcspFailure.Malformed)
    }

    /**
     * Verifies [response] and returns its answer about [certificate].
     *
     * The response must be successful and signed with an algorithm the policy accepts, either by [issuer] itself or
     * by a delegated responder: a certificate in the response that [issuer] issued and signed, that names
     * id-kp-OCSPSigning in its extended key usage, permits digital signatures and is valid at the time of
     * verification. The revocation of a delegated responder is never checked; [OcspParameters.isNoCheckRequired]
     * demands that the issuer marked it with ocsp-nocheck. When [request] carries a nonce, a response that carries
     * another one fails; one without a nonce passes unless [OcspParameters.isNonceRequired]. The answer about
     * [certificate] is found by its serial number and the digests of [issuer], recomputed with the digest of the
     * answer if the policy accepts it. It must have been produced no later than the time of verification and stay
     * valid until then, both with the skew of [parameters]; an answer without a next update is valid for
     * [OcspParameters.maximumAge].
     *
     * @param response the response.
     * @param certificate the certificate whose status is asked.
     * @param issuer the issuer of [certificate].
     * @param request the request the response answers, or null for a response that was not asked for, such as one
     *   stapled to a TLS handshake.
     * @param parameters the parameters of the verification.
     * @return the answer about [certificate], or why the response does not vouch for it.
     * @since 1.0.0
     */
    public suspend fun verify(
        response: OcspResponse,
        certificate: Certificate,
        issuer: OcspIssuer,
        request: OcspRequest? = null,
        parameters: OcspParameters = OcspParameters(),
    ): Outcome<SingleResponse, OcspFailure> = verifier.verify(
        response = response,
        certificate = certificate,
        issuer = issuer,
        nonce = request?.nonce,
        parameters = parameters,
    )

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Ocsp($limits)"

    /**
     * The sizes of nonces.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of the nonce of a request, as RFC 9654 recommends.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_NONCE_SIZE: Int = MINIMUM_NONCE_BYTES

        /**
         * The smallest nonce of a request RFC 9654 permits.
         *
         * @since 1.0.0
         */
        public const val MINIMUM_NONCE_SIZE: Int = MINIMUM_NONCE_BYTES

        /**
         * The largest nonce RFC 9654 permits, in a request or a response.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_NONCE_SIZE: Int = MAXIMUM_NONCE_BYTES
    }
}
