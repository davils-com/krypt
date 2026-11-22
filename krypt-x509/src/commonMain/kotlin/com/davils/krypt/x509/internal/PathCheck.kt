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

package com.davils.krypt.x509.internal

import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.internal.PathRefusal.Companion.ensure
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.path.PathFailure
import com.davils.krypt.x509.path.PathValidation
import com.davils.krypt.x509.path.RevocationChecker
import com.davils.krypt.x509.path.RevocationStatus
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import kotlin.time.Instant

internal class PathCheck(
    private val crypto: Crypto,
    private val revocation: RevocationChecker?,
    private val parameters: ValidationParameters,
    private val at: Instant,
) {
    suspend fun check(path: List<Certificate>, anchor: TrustAnchor): PathValidation = try {
        run(path, anchor)
    } catch (refusal: PathRefusal) {
        PathValidation.Invalid(refusal.failure, refusal.certificate)
    }

    private suspend fun run(path: List<Certificate>, anchor: TrustAnchor): PathValidation.Valid {
        val ordered = path.reversed()
        val state = State(
            key = anchor.publicKey,
            name = anchor.name,
            issuer = anchor.certificate,
            remaining = ordered.size,
            constraints = listOfNotNull(anchor.nameConstraints).toMutableList(),
            policies = PolicyState(parameters, ordered.size),
        )
        ordered.forEachIndexed { index, certificate ->
            val isLast = index == ordered.size - 1
            checkBasics(certificate = certificate, state = state, anchor = anchor, isLast = isLast)
            when (isLast) {
                true -> checkLeaf(certificate)
                false -> prepareNext(certificate, state)
            }
        }
        val policies = state.policies.finish(ordered.last()) ?: throw PathRefusal(PathFailure.Policy, ordered.last())
        return PathValidation.Valid(path = path, anchor = anchor, policies = policies)
    }

    private suspend fun checkBasics(certificate: Certificate, state: State, anchor: TrustAnchor, isLast: Boolean) {
        val algorithm = certificate.signatureAlgorithm
        val isPermitted = algorithm != null && crypto.environment.policy.permits(algorithm, AlgorithmUse.Verify)
        ensure(isPermitted, PathFailure.AlgorithmNotPermitted, certificate)
        val verification = SignatureChecks.verify(
            crypto = crypto,
            algorithm = algorithm,
            key = state.key,
            data = certificate.tbs,
            signature = certificate.signature,
        )
        ensure(verification.isValid, PathFailure.BadSignature, certificate)
        ensure(certificate.isValidAt(at), PathFailure.Expired, certificate)
        ensure(certificate.issuer == state.name, PathFailure.NoTrustedPath, certificate)
        checkRevocation(certificate = certificate, issuer = state.issuer, anchor = anchor)
        val isChecked = !(certificate.isSelfIssued && !isLast)
        ensure(
            !isChecked || NameChecks.isPermitted(certificate, state.constraints),
            PathFailure.NameConstraints,
            certificate,
        )
        ensure(state.policies.process(certificate, isLast), PathFailure.Policy, certificate)
        ensure(certificate.extensions.unknownCritical.isEmpty(), PathFailure.UnknownCriticalExtension, certificate)
    }

    private suspend fun checkRevocation(certificate: Certificate, issuer: Certificate?, anchor: TrustAnchor) {
        val status = revocation?.check(certificate = certificate, issuer = issuer, anchor = anchor, at = at)
        ensure(status != RevocationStatus.Revoked, PathFailure.Revoked, certificate)
        val isKnown = status != RevocationStatus.Unknown || !parameters.isRevocationRequired
        ensure(isKnown, PathFailure.RevocationUnknown, certificate)
    }

    private fun checkLeaf(certificate: Certificate) {
        ensure(certificate.publicKey != null, PathFailure.AlgorithmNotPermitted, certificate)
        val purposes = certificate.extensions.extendedKeyUsage
        val purpose = parameters.purpose
        val isAllowed = purpose == null || purposes == null || purpose in purposes
        ensure(isAllowed, PathFailure.Purpose, certificate)
    }

    private fun prepareNext(certificate: Certificate, state: State) {
        ensure(certificate.isCa, PathFailure.NotAnAuthority, certificate)
        val usages = certificate.extensions.keyUsage
        ensure(usages == null || KeyUsage.KeyCertSign in usages, PathFailure.KeyUsage, certificate)
        val purposes = certificate.extensions.extendedKeyUsage
        val purpose = parameters.purpose
        val isAllowed = purpose == null || purposes == null || purpose in purposes || KeyPurposes.Any in purposes
        ensure(isAllowed, PathFailure.Purpose, certificate)
        val isSelfIssued = certificate.isSelfIssued
        ensure(isSelfIssued || state.remaining > 0, PathFailure.PathTooLong, certificate)
        val decremented = state.remaining - listOf(1, 0)[isSelfIssued.compareTo(false)]
        val constraint = certificate.extensions.basicConstraints?.pathLength ?: decremented
        state.remaining = minOf(a = decremented, b = constraint)
        certificate.extensions.nameConstraints?.let { constraints -> state.constraints += constraints }
        state.key = certificate.publicKey ?: throw PathRefusal(PathFailure.AlgorithmNotPermitted, certificate)
        state.name = certificate.subject
        state.issuer = certificate
        ensure(state.policies.prepare(certificate), PathFailure.Policy, certificate)
    }

    private class State(
        var key: PublicKey,
        var name: DistinguishedName,
        var issuer: Certificate?,
        var remaining: Int,
        val constraints: MutableList<NameConstraints>,
        val policies: PolicyState,
    )
}
