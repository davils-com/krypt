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

package com.davils.krypt.ocsp.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.ocsp.BasicOcspResponse
import com.davils.krypt.ocsp.OcspFailure
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.ocsp.OcspParameters
import com.davils.krypt.ocsp.OcspResponse
import com.davils.krypt.ocsp.SingleResponse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal class ResponseVerifier(private val crypto: Crypto, private val certificates: Certificates) {
    suspend fun verify(
        response: OcspResponse,
        certificate: Certificate,
        issuer: OcspIssuer,
        nonce: ByteString?,
        parameters: OcspParameters,
    ): Outcome<SingleResponse, OcspFailure> {
        val basic = response.basic ?: return Outcome.Failure(OcspFailure.ResponderError)
        val at = parameters.at ?: crypto.environment.clock.now()
        val signatureFailure = signatureFailure(basic = basic, issuer = issuer, at = at, parameters = parameters)
        val failure = signatureFailure ?: nonceFailure(received = basic.nonce, sent = nonce, parameters = parameters)
        val refused = failure?.let { found -> Outcome.Failure(found) }
        return refused ?: matched(
            basic = basic,
            certificate = certificate,
            issuer = issuer,
            at = at,
            parameters = parameters,
        )
    }

    private suspend fun signatureFailure(
        basic: BasicOcspResponse,
        issuer: OcspIssuer,
        at: Instant,
        parameters: OcspParameters,
    ): OcspFailure? {
        val policy = crypto.environment.policy
        val algorithm = basic.signatureAlgorithm?.takeIf { found -> policy.permits(found, AlgorithmUse.Verify) }
            ?: return OcspFailure.AlgorithmNotPermitted
        val isIssuerSigned = SignatureChecks.isValid(
            crypto = crypto,
            algorithm = algorithm,
            key = issuer.publicKey,
            data = basic.tbs,
            signature = basic.signature,
        )
        val candidates = basic.certificates.takeUnless { isIssuerSigned }.orEmpty()
        val signers = candidates.filter { candidate -> isSigner(candidate, basic, algorithm) }
        val isDelegated = signers.any { signer ->
            isAuthorized(responder = signer, issuer = issuer, at = at, parameters = parameters)
        }
        val failure = listOf(OcspFailure.BadSignature, OcspFailure.UnauthorizedResponder)
        return failure[signers.isNotEmpty().compareTo(false)].takeUnless { isIssuerSigned || isDelegated }
    }

    private suspend fun isSigner(
        candidate: Certificate,
        basic: BasicOcspResponse,
        algorithm: SignatureAlgorithm,
    ): Boolean {
        val key = candidate.publicKey ?: return false
        return SignatureChecks.isValid(
            crypto = crypto,
            algorithm = algorithm,
            key = key,
            data = basic.tbs,
            signature = basic.signature,
        )
    }

    private suspend fun isAuthorized(
        responder: Certificate,
        issuer: OcspIssuer,
        at: Instant,
        parameters: OcspParameters,
    ): Boolean {
        val extensions = responder.extensions
        val isOcspSigner = KeyPurposes.OcspSigning in extensions.extendedKeyUsage.orEmpty()
        val isSigning = extensions.keyUsage?.let { usages -> KeyUsage.DigitalSignature in usages } != false
        val isNoCheckMet = !parameters.isNoCheckRequired || extensions.isOcspNoCheck
        val isFit = responder.issuer == issuer.name && isOcspSigner && isSigning && isNoCheckMet
        val isCurrent = isFit && responder.isValidAt(at)
        return isCurrent && certificates.verifySignature(responder, issuer.publicKey).isValid
    }

    private fun nonceFailure(received: ByteString?, sent: ByteString?, parameters: OcspParameters): OcspFailure? {
        val isMismatch = sent != null && received != null && received != sent
        val isMissing = parameters.isNonceRequired && (sent == null || received != sent)
        return OcspFailure.NonceMismatch.takeIf { isMismatch || isMissing }
    }

    private suspend fun matched(
        basic: BasicOcspResponse,
        certificate: Certificate,
        issuer: OcspIssuer,
        at: Instant,
        parameters: OcspParameters,
    ): Outcome<SingleResponse, OcspFailure> {
        val serial = certificate.serialNumber
        val candidates = basic.responses.filter { response ->
            response.certId.serialNumber == serial && CertIds.isPermitted(crypto, response.certId.hashAlgorithm)
        }
        val match = candidates.firstOrNull { response ->
            val expected = CertIds.of(
                crypto = crypto,
                issuer = issuer,
                serialNumber = serial,
                algorithm = response.certId.hashAlgorithm,
            )
            expected == response.certId
        } ?: return Outcome.Failure(OcspFailure.NotFound)
        val horizon = match.nextUpdate ?: (match.thisUpdate + parameters.maximumAge)
        val isFresh = match.thisUpdate <= at + parameters.skew && horizon >= at - parameters.skew
        val success: Outcome<SingleResponse, OcspFailure> = Outcome.Success(match)
        return success.takeIf { isFresh } ?: Outcome.Failure(OcspFailure.Stale)
    }
}
