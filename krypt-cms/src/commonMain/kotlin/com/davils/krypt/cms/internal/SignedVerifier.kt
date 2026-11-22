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
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.internal.EssCertId.Companion.readFirstCertId
import com.davils.krypt.cms.signed.SignatureParameters
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.cms.signed.SignerInfo
import com.davils.krypt.cms.signed.VerifiedSigner
import com.davils.krypt.core.ConstantTime
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.PathValidation
import kotlinx.io.bytestring.ByteString

internal class SignedVerifier(
    private val crypto: Crypto,
    private val codec: SignedCodec,
    private val limits: CmsLimits,
) {
    suspend fun verify(
        data: SignedData,
        signer: SignerInfo,
        content: ByteString?,
        parameters: SignatureParameters,
    ): Outcome<VerifiedSigner, CmsFailure> {
        val covered = content ?: data.content ?: return Outcome.Failure(CmsFailure.ContentMissing)
        return checked(
            pool = data.certificates + parameters.certificates,
            signer = signer,
            target = Target(data = covered, contentType = data.contentType),
            parameters = parameters,
        )
    }

    suspend fun verifyCountersignature(
        data: SignedData,
        target: SignerInfo,
        countersignature: SignerInfo,
        parameters: SignatureParameters,
    ): Outcome<VerifiedSigner, CmsFailure> = checked(
        pool = data.certificates + parameters.certificates,
        signer = countersignature,
        target = Target(data = target.signature, contentType = null),
        parameters = parameters,
    )

    private suspend fun checked(
        pool: List<Certificate>,
        signer: SignerInfo,
        target: Target,
        parameters: SignatureParameters,
    ): Outcome<VerifiedSigner, CmsFailure> = try {
        verified(pool = pool, signer = signer, target = target, parameters = parameters)
    } catch (ignored: PolicyViolationException) {
        Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
    } catch (ignored: CryptoException) {
        Outcome.Failure(CmsFailure.BadSignature)
    }

    private suspend fun verified(
        pool: List<Certificate>,
        signer: SignerInfo,
        target: Target,
        parameters: SignatureParameters,
    ): Outcome<VerifiedSigner, CmsFailure> {
        val certificate = pool.firstOrNull { candidate -> signer.identifier.matches(candidate) }
            ?: return Outcome.Failure(CmsFailure.SignerNotFound)
        return verifiedBy(
            certificate = certificate,
            checks = Checks(pool = pool, signer = signer, target = target, parameters = parameters),
        )
    }

    private suspend fun verifiedBy(certificate: Certificate, checks: Checks): Outcome<VerifiedSigner, CmsFailure> {
        val signer = checks.signer
        val usable = usableOf(signer, certificate) ?: return Outcome.Failure(CmsFailure.AlgorithmNotPermitted)
        val failure = attributeFailure(signer = signer, certificate = certificate, target = checks.target)
            ?: signatureFailure(usable = usable, signer = signer, target = checks.target)
        val parameters = checks.parameters
        val path = parameters.validator?.takeIf { failure == null }?.validate(
            leaf = certificate,
            intermediates = checks.pool,
            parameters = parameters.validation,
        )
        val result = failure ?: CmsFailure.UntrustedSigner.takeIf { path?.isValid == false }
        val verified = VerifiedSigner(signer = signer, certificate = certificate, path = path as? PathValidation.Valid)
        return result?.let { found -> Outcome.Failure(found) } ?: Outcome.Success(verified)
    }

    private suspend fun usableOf(signer: SignerInfo, certificate: Certificate): Usable? {
        val algorithm = signer.signatureAlgorithm
        val key = certificate.publicKey
        if (key == null || algorithm == null) return null
        val permitted = Usable(key, algorithm).takeIf { found -> isUsable(found, signer) }
        return permitted?.takeIf { found -> crypto.capabilities.supports(found.algorithm) }
    }

    private fun isUsable(usable: Usable, signer: SignerInfo): Boolean {
        val policy = crypto.environment.policy
        val key = usable.key
        val algorithm = usable.algorithm
        val isRsaPermitted = key.family != KeyFamily.Rsa || policy.permitsRsa(key.bits, AlgorithmUse.Verify)
        val isCurvePermitted = key.curve?.let { curve -> policy.permitsCurve(curve) } != false
        val isDigestConsistent = algorithm.digest == null || algorithm.digest == signer.digestAlgorithm
        val isPermitted = policy.permits(algorithm, AlgorithmUse.Verify) && algorithm.family == key.family
        return isPermitted && isRsaPermitted && isCurvePermitted && isDigestConsistent
    }

    private suspend fun attributeFailure(signer: SignerInfo, certificate: Certificate, target: Target): CmsFailure? {
        val signed = signer.parts.signed ?: return null
        return signedFailure(
            signed = signed,
            digest = signer.digestAlgorithm,
            certificate = certificate,
            target = target,
        )
    }

    private suspend fun signedFailure(
        signed: SignedAttributes,
        digest: DigestAlgorithm?,
        certificate: Certificate,
        target: Target,
    ): CmsFailure? {
        val algorithm = digest ?: return CmsFailure.AlgorithmNotPermitted
        val expected = crypto.digests.digest(data = target.data, algorithm = algorithm, use = AlgorithmUse.Verify)
        val isDigest = ConstantTime.equals(first = expected, second = signed.messageDigest)
        val isContentType = signed.contentType == target.contentType
        val failure = essFailure(signed.set, certificate) ?: CmsFailure.AttributeMismatch.takeUnless { isContentType }
        return failure ?: CmsFailure.DigestMismatch.takeUnless { isDigest }
    }

    private suspend fun essFailure(signed: AttributeSet, certificate: Certificate): CmsFailure? {
        val version2 = AttributeCodec.single(signed, CmsOids.SIGNING_CERTIFICATE_V2)
        val value = version2 ?: AttributeCodec.single(signed, CmsOids.SIGNING_CERTIFICATE) ?: return null
        return essMismatch(value = value, isVersion2 = version2 != null, certificate = certificate)
    }

    private suspend fun essMismatch(value: ByteString, isVersion2: Boolean, certificate: Certificate): CmsFailure? {
        val id = Der.decodeOrNull(value, codec.derLimits) {
            readFirstCertId(isVersion2 = isVersion2, maximum = limits.maximumCertificates)
        } ?: return CmsFailure.AttributeMismatch
        return idMismatch(id, certificate)
    }

    private suspend fun idMismatch(id: EssCertId, certificate: Certificate): CmsFailure? {
        val digest = id.digest ?: return CmsFailure.AlgorithmNotPermitted
        val hash = crypto.digests.digest(data = certificate.encoded, algorithm = digest, use = AlgorithmUse.Verify)
        val isMatch = hash == id.hash && id.isIssuerSerialOf(certificate)
        return CmsFailure.AttributeMismatch.takeUnless { isMatch }
    }

    private suspend fun signatureFailure(usable: Usable, signer: SignerInfo, target: Target): CmsFailure? {
        val input = signer.parts.signed.mapOr(absent = { target.data }, present = { signed -> signed.encoded })
        val verification = crypto.signatures.verify(
            key = usable.key,
            data = input,
            signature = signer.signature,
            algorithm = usable.algorithm,
        )
        return CmsFailure.BadSignature.takeUnless { verification.isValid }
    }

    private data class Target(val data: ByteString, val contentType: ObjectIdentifier?)

    private data class Usable(val key: PublicKey, val algorithm: SignatureAlgorithm)

    private data class Checks(
        val pool: List<Certificate>,
        val signer: SignerInfo,
        val target: Target,
        val parameters: SignatureParameters,
    )
}
