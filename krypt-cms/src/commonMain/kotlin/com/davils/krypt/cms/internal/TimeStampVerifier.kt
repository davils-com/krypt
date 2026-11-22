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

package com.davils.krypt.cms.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.timestamp.TimeStampParameters
import com.davils.krypt.cms.timestamp.TimeStampToken
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.KeyPurposes
import kotlinx.io.bytestring.ByteString

internal class TimeStampVerifier(private val cms: Cms) {
    suspend fun verifyData(
        token: TimeStampToken,
        digest: DigestAlgorithm,
        data: ByteString,
        parameters: TimeStampParameters,
    ): Outcome<TimeStampToken, CmsFailure> = guarded {
        val hashed = cms.crypto.digests.digest(data = data, algorithm = digest, use = AlgorithmUse.Verify)
        verified(token = token, digest = digest, hashedMessage = hashed, parameters = parameters)
    }

    suspend fun verify(
        token: TimeStampToken,
        digest: DigestAlgorithm,
        hashedMessage: ByteString,
        parameters: TimeStampParameters,
    ): Outcome<TimeStampToken, CmsFailure> = guarded {
        verified(token = token, digest = digest, hashedMessage = hashedMessage, parameters = parameters)
    }

    private suspend fun verified(
        token: TimeStampToken,
        digest: DigestAlgorithm,
        hashedMessage: ByteString,
        parameters: TimeStampParameters,
    ): Outcome<TimeStampToken, CmsFailure> {
        val signedData = token.signedData
        val signer = signedData.signers.single()
        val isBound = signer.parts.signed?.let { signed -> hasSigningCertificate(signed.set) } == true
        if (!isBound) return Outcome.Failure(CmsFailure.AttributeMismatch)
        val expected = Expected(digest = digest, hashedMessage = hashedMessage, parameters = parameters)
        return when (
            val verification = cms.verifySigner(
                signedData = signedData,
                signer = signer,
                parameters = parameters.signature,
            )
        ) {
            is Outcome.Success -> checked(
                token = token,
                certificate = verification.value.certificate,
                expected = expected,
            )

            is Outcome.Failure -> Outcome.Failure(verification.failure)
        }
    }

    private fun checked(
        token: TimeStampToken,
        certificate: Certificate,
        expected: Expected,
    ): Outcome<TimeStampToken, CmsFailure> {
        val info = token.info
        val parameters = expected.parameters
        val isImprint = info.digest == expected.digest && info.hashedMessage == expected.hashedMessage
        val isNonce = parameters.nonce == null || info.nonce == parameters.nonce
        val isPolicy = parameters.policy == null || info.policy == parameters.policy
        val isCarried = !parameters.isCertificateRequired || certificate in token.signedData.certificates
        val failure = CmsFailure.UnauthorizedTimeStampAuthority.takeIf { !isTimeStamping(certificate) }
            ?: CmsFailure.TimeStampMismatch.takeUnless { isImprint && isNonce && isPolicy && isCarried }
        return failure?.let { found -> Outcome.Failure(found) } ?: Outcome.Success(token)
    }

    private inline fun guarded(block: () -> Outcome<TimeStampToken, CmsFailure>): Outcome<TimeStampToken, CmsFailure> =
        try {
            block()
        } catch (ignored: CryptoException) {
            Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
        }

    private fun hasSigningCertificate(signed: AttributeSet): Boolean {
        val types = signed.attributes.map { attribute -> attribute.type }
        return CmsOids.SIGNING_CERTIFICATE_V2 in types || CmsOids.SIGNING_CERTIFICATE in types
    }

    private data class Expected(
        val digest: DigestAlgorithm,
        val hashedMessage: ByteString,
        val parameters: TimeStampParameters,
    )

    companion object {
        fun isTimeStamping(certificate: Certificate): Boolean {
            val extensions = certificate.extensions
            val isCritical = extensions[ExtensionIds.ExtendedKeyUsage]?.isCritical == true
            return isCritical && extensions.extendedKeyUsage == listOf(KeyPurposes.TimeStamping)
        }
    }
}
