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

package com.davils.krypt.cms.timestamp

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.Attribute
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.internal.CmsOids
import com.davils.krypt.cms.internal.TimeStampCodec
import com.davils.krypt.cms.internal.TimeStampVerifier
import com.davils.krypt.cms.signed.SignatureParameters
import com.davils.krypt.cms.signed.SignerInfo
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

/**
 * Time stamps of RFC 3161 with the ESSCertIDv2 of RFC 5816: requests, responses, tokens and the signature time
 * stamp of a CMS signer.
 *
 * krypt sends nothing: the caller carries the request to the authority, such as by HTTP POST with the media type
 * application/timestamp-query, and the response back. Every encoding is read as strict DER within [limits]. The
 * object holds no key and is safe to share between threads.
 *
 * @property crypto the primitives and their policy.
 * @property limits the limits of reading.
 * @constructor Works with [crypto] within [limits].
 * @since 1.0.0
 */
public class TimeStamps(public val crypto: Crypto, public val limits: CmsLimits = CmsLimits.Default) {
    private val cms = Cms(crypto, limits)
    private val codec = TimeStampCodec(cms.signedCodec, limits)
    private val verifier = TimeStampVerifier(cms)

    /**
     * Builds a request for a time stamp of [data].
     *
     * @param data the message whose digest is time-stamped.
     * @param digest SHA-256, SHA-384 or SHA-512.
     * @param policy the policy to ask for, or null for the authority's default.
     * @param isCertificateRequested true to ask for the authority's certificate in the token.
     * @param nonceBytes the size of a random nonce, [MINIMUM_NONCE_SIZE] to [MAXIMUM_NONCE_SIZE] bytes, or null.
     * @return the request.
     * @throws IllegalArgumentException if [digest] is not SHA-2 or the nonce size is out of range.
     * @since 1.0.0
     */
    public suspend fun request(
        data: ByteString,
        digest: DigestAlgorithm = DigestAlgorithm.Sha256,
        policy: ObjectIdentifier? = null,
        isCertificateRequested: Boolean = true,
        nonceBytes: Int? = DEFAULT_NONCE_SIZE,
    ): TimeStampRequest {
        require(nonceBytes == null || nonceBytes in MINIMUM_NONCE_SIZE..MAXIMUM_NONCE_SIZE) {
            "A nonce has $MINIMUM_NONCE_SIZE to $MAXIMUM_NONCE_SIZE bytes"
        }
        val random = crypto.environment.random
        val nonce = nonceBytes?.let { count -> DerInteger.ofMagnitude(ByteString(random.bytes(count))) }
        val hashed = crypto.digests.digest(data = data, algorithm = digest)
        val encoded = codec.encodeRequest(
            digest = digest,
            hashedMessage = hashed,
            policy = policy,
            nonce = nonce,
            isCertificateRequested = isCertificateRequested,
        )
        return TimeStampRequest(
            digest = digest,
            hashedMessage = hashed,
            policy = policy,
            nonce = nonce,
            isCertificateRequested = isCertificateRequested,
            hasExtensions = false,
            encoded = encoded,
        )
    }

    /**
     * Reads a request in DER, as an authority does.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the request, or [CmsFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeRequest(encoded: ByteString): Outcome<TimeStampRequest, CmsFailure> {
        val decoded = codec.decodeRequest(encoded)?.let { found -> Outcome.Success(found) }
        return decoded ?: Outcome.Failure(CmsFailure.Malformed)
    }

    /**
     * Reads a response in DER.
     *
     * A token must be signed data of exactly one signer over a TSTInfo.
     *
     * @param encoded the encoding, possibly from an attacker.
     * @return the response, which is not verified yet, or [CmsFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeResponse(encoded: ByteString): Outcome<TimeStampResponse, CmsFailure> {
        val decoded = codec.decodeResponse(encoded)?.let { found -> Outcome.Success(found) }
        return decoded ?: Outcome.Failure(CmsFailure.Malformed)
    }

    /**
     * Reads a time-stamp token in DER, such as one of [SignerInfo.timeStampTokens].
     *
     * @param encoded the encoding of the token's ContentInfo, possibly from an attacker.
     * @return the token, which is not verified yet, or [CmsFailure.Malformed].
     * @since 1.0.0
     */
    public fun decodeToken(encoded: ByteString): Outcome<TimeStampToken, CmsFailure> {
        val decoded = codec.decodeToken(encoded)?.let { found -> Outcome.Success(found) }
        return decoded ?: Outcome.Failure(CmsFailure.Malformed)
    }

    /**
     * Verifies that [response] answers [request].
     *
     * The status must grant a token. The token's signature must verify as [Cms.verifySigner] does, its signed
     * attributes must carry an ESS signing-certificate attribute that names the authority's certificate, and that
     * certificate must carry the critical extended key usage id-kp-timeStamping as its only purpose. The TSTInfo must
     * repeat the imprint, the nonce and the requested policy of [request], and the token must carry the authority's
     * certificate if [request] asked for it.
     *
     * @param response the response.
     * @param request the request it answers.
     * @param parameters the certificates and the path validation of the authority's certificate.
     * @return the token, or why it does not answer the request.
     * @since 1.0.0
     */
    public suspend fun verify(
        response: TimeStampResponse,
        request: TimeStampRequest,
        parameters: SignatureParameters = SignatureParameters(),
    ): Outcome<TimeStampToken, CmsFailure> {
        val token = response.token?.takeIf { response.status.isGranted }
            ?: return Outcome.Failure(CmsFailure.TimeStampRejected)
        return verify(token = token, request = request, parameters = parameters)
    }

    private suspend fun verify(
        token: TimeStampToken,
        request: TimeStampRequest,
        parameters: SignatureParameters,
    ): Outcome<TimeStampToken, CmsFailure> {
        val digest = request.digest ?: return Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
        val expectations = TimeStampParameters(
            signature = parameters,
            nonce = request.nonce,
            policy = request.policy,
            isCertificateRequired = request.isCertificateRequested,
        )
        return verifier.verify(
            token = token,
            digest = digest,
            hashedMessage = request.hashedMessage,
            parameters = expectations,
        )
    }

    /**
     * Verifies that [token] time-stamps [data], as [verify] does for a response.
     *
     * @param token the token.
     * @param data the time-stamped message.
     * @param parameters what the token must satisfy.
     * @return the token, or why it does not vouch for [data].
     * @since 1.0.0
     */
    public suspend fun verifyToken(
        token: TimeStampToken,
        data: ByteString,
        parameters: TimeStampParameters = TimeStampParameters(),
    ): Outcome<TimeStampToken, CmsFailure> {
        val digest = token.info.digest ?: return Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
        val hashed = crypto.digests.digest(data = data, algorithm = digest)
        return verifier.verify(token = token, digest = digest, hashedMessage = hashed, parameters = parameters)
    }

    /**
     * Returns the signature-time-stamp attribute of RFC 3161 appendix A with [token], to add to the unsigned
     * attributes of a signer with [Cms.addUnsignedAttribute]. The token must time-stamp the signer's signature value,
     * as a request for [SignerInfo.signature] yields.
     *
     * @param token the token.
     * @return the attribute.
     * @since 1.0.0
     */
    public fun signatureTimeStamp(token: TimeStampToken): Attribute =
        Attribute(CmsOids.TIME_STAMP_TOKEN, listOf(token.encoded))

    /**
     * Verifies every signature time stamp of [signer]: each token must time-stamp the signer's signature value.
     *
     * @param signer the signer.
     * @param parameters what every token must satisfy.
     * @return the tokens, or the first failure; an empty list if the signer has none.
     * @since 1.0.0
     */
    public suspend fun verifySignatureTimeStamps(
        signer: SignerInfo,
        parameters: TimeStampParameters = TimeStampParameters(),
    ): Outcome<List<TimeStampToken>, CmsFailure> {
        val verified = mutableListOf<TimeStampToken>()
        val failure = signer.timeStampTokens.firstNotNullOfOrNull { encoded ->
            val outcome = when (val decoded = decodeToken(encoded)) {
                is Outcome.Success -> verifyToken(
                    token = decoded.value,
                    data = signer.signature,
                    parameters = parameters,
                )

                is Outcome.Failure -> decoded
            }
            when (outcome) {
                is Outcome.Success -> null.also { verified += outcome.value }
                is Outcome.Failure -> outcome.failure
            }
        }
        return failure?.let { found -> Outcome.Failure(found) } ?: Outcome.Success(verified.toList())
    }

    /**
     * Shows the limits.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TimeStamps($limits)"

    /**
     * The sizes of nonces.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a nonce.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_NONCE_SIZE: Int = 16

        /**
         * The smallest nonce krypt sends.
         *
         * @since 1.0.0
         */
        public const val MINIMUM_NONCE_SIZE: Int = 8

        /**
         * The largest nonce krypt sends.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_NONCE_SIZE: Int = 32
    }
}
