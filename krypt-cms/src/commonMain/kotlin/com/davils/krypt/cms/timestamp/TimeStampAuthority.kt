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

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.internal.TimeStampCodec
import com.davils.krypt.cms.internal.TimeStampVerifier
import com.davils.krypt.cms.internal.TstParts
import com.davils.krypt.cms.internal.mapOr
import com.davils.krypt.cms.signed.SignedDataBuilder
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * The logic of a time-stamp authority by RFC 3161 with the ESSCertIDv2 of RFC 5816: it answers requests with tokens
 * that its [Signer] signs, possibly with a key in an HSM.
 *
 * Serial numbers are 128 random bits from the environment and the time comes from its clock, both of which the
 * operator must keep trustworthy. A request for an unknown digest, an unaccepted policy or with extensions is
 * rejected with the matching PKIFailureInfo. krypt transports nothing and keeps no state; the object is safe to share
 * between threads.
 *
 * @property crypto the primitives, their policy, the randomness and the clock.
 * @param signer the signer of the authority.
 * @property certificate the authority's certificate, with the critical extended key usage id-kp-timeStamping as its
 *   only purpose.
 * @property policy the default policy of the tokens.
 * @param policies further policies the authority accepts on request.
 * @property accuracy the accuracy of the clock, or null to state none.
 * @param chain the certificates above [certificate], carried in a token when the request asks for certificates.
 * @param digests the digests of imprints the authority accepts.
 * @property limits the limits of reading requests and writing tokens.
 * @constructor Configures the authority.
 * @throws IllegalArgumentException if [certificate] is not a time-stamping certificate of [signer]'s key.
 * @since 1.0.0
 */
public class TimeStampAuthority(
    public val crypto: Crypto,
    private val signer: Signer,
    public val certificate: Certificate,
    public val policy: ObjectIdentifier,
    policies: Set<ObjectIdentifier> = emptySet(),
    public val accuracy: Accuracy? = null,
    chain: List<Certificate> = emptyList(),
    digests: Set<DigestAlgorithm> = setOf(DigestAlgorithm.Sha256, DigestAlgorithm.Sha384, DigestAlgorithm.Sha512),
    public val limits: CmsLimits = CmsLimits.Default,
) {
    private val cms = Cms(crypto, limits)
    private val codec = TimeStampCodec(cms.signedCodec, limits)
    private val accepted = policies + policy
    private val chain = chain.toList()
    private val digests = digests.toSet()

    init {
        require(certificate.publicKey == signer.publicKey) { "The certificate is not the one of the signer" }
        require(TimeStampVerifier.isTimeStamping(certificate)) {
            "A time-stamp authority's certificate has the critical extended key usage id-kp-timeStamping alone"
        }
    }

    /**
     * Answers an encoded request.
     *
     * @param request the encoding of a TimeStampReq, possibly from an attacker.
     * @return the encoding of the TimeStampResp: a granted token, or a rejection with badDataFormat for a request
     *   krypt cannot read.
     * @since 1.0.0
     */
    public suspend fun respond(request: ByteString): ByteString {
        val decoded = codec.decodeRequest(request) ?: return rejection(BAD_DATA_FORMAT, "The request is malformed")
        return respond(decoded)
    }

    /**
     * Answers [request].
     *
     * @param request the request.
     * @return the encoding of the TimeStampResp: a granted token or a rejection.
     * @since 1.0.0
     */
    public suspend fun respond(request: TimeStampRequest): ByteString {
        val digest = request.digest?.takeIf { found -> found in digests }
            ?: return rejection(BAD_ALGORITHM, "The digest is not accepted")
        return respond(request = request, digest = digest)
    }

    private suspend fun respond(request: TimeStampRequest, digest: DigestAlgorithm): ByteString {
        val chosen = request.policy ?: policy
        val refusal = (UNACCEPTED_EXTENSION to "Extensions are not supported").takeIf { request.hasExtensions }
            ?: (UNACCEPTED_POLICY to "The policy is not accepted").takeUnless { chosen in accepted }
        return refusal.mapOr(
            absent = { granted(request = request, digest = digest, chosen = chosen) },
            present = { (bit, text) -> rejection(bit, text) },
        )
    }

    private suspend fun granted(
        request: TimeStampRequest,
        digest: DigestAlgorithm,
        chosen: ObjectIdentifier,
    ): ByteString {
        val now = crypto.environment.clock.now()
        val genTime = Instant.fromEpochMilliseconds(now.toEpochMilliseconds())
        val serial = DerInteger.ofMagnitude(ByteString(crypto.environment.random.bytes(SERIAL_BYTES)))
        val parts = TstParts(
            policy = chosen,
            digest = digest,
            hashedMessage = request.hashedMessage,
            serialNumber = serial,
            genTime = genTime,
            accuracy = accuracy,
            isOrdered = false,
            nonce = request.nonce,
            encoded = ByteString(),
        )
        val builder = SignedDataBuilder()
        builder.contentType = ContentTypes.TstInfo
        builder.signer(signer, certificate) {
            isCertificateIncluded = request.isCertificateRequested
            signingTime = genTime
        }
        if (request.isCertificateRequested) builder.certificates(chain)
        val token = cms.signedWriter.sign(codec.encodeTstInfo(parts, digest), builder)
        return codec.encodeResponse(status = TimeStampStatus.Granted, text = null, failures = emptySet(), token = token)
    }

    private fun rejection(bit: Int, text: String): ByteString =
        codec.encodeResponse(status = TimeStampStatus.Rejection, text = text, failures = setOf(bit), token = null)

    /**
     * Shows the certificate's subject and the policy.
     *
     * @return the authority as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TimeStampAuthority(${certificate.subject}, ${policy.dotted})"

    private companion object {
        const val SERIAL_BYTES: Int = 16
        const val BAD_ALGORITHM: Int = 0
        const val BAD_DATA_FORMAT: Int = 5
        const val UNACCEPTED_POLICY: Int = 15
        const val UNACCEPTED_EXTENSION: Int = 16
    }
}
