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

import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.ct.Transparency
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.ocsp.OcspResponseSource
import com.davils.krypt.ocsp.OcspRevocationChecker
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.peer.Authorization
import com.davils.krypt.tls.peer.PeerAuthorizer
import com.davils.krypt.tls.peer.PeerIdentity
import com.davils.krypt.tls.trust.RevocationMode
import com.davils.krypt.tls.trust.TrustFailure
import com.davils.krypt.tls.trust.TrustRefusedException
import com.davils.krypt.tls.trust.TrustSettings
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.crl.RevocationLists
import com.davils.krypt.x509.path.CrlRevocationChecker
import com.davils.krypt.x509.path.PathValidation
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.RevocationChecker
import com.davils.krypt.x509.path.RevocationListSource
import com.davils.krypt.x509.path.ServiceIdentity
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters

internal class TrustCheck(
    private val crypto: Crypto,
    private val settings: TrustSettings,
    private val purpose: ObjectIdentifier,
    private val authorizer: PeerAuthorizer?,
) {
    private val ocsp: Ocsp = Ocsp(crypto)

    private val transparency: Transparency = Transparency(crypto)

    private val sources: List<RevocationChecker> = listOfNotNull(
        settings.ocspSource?.let { source -> OcspRevocationChecker(ocsp, contained(source)) },
        settings.revocationListSource?.let { source ->
            CrlRevocationChecker(RevocationLists(crypto, settings.limits), contained(source))
        },
    )

    suspend fun check(handshake: Handshake, anchors: List<TrustAnchor>): PeerIdentity {
        val chain = handshake.chain
        val revocation = HandshakeRevocation(
            ocsp = ocsp,
            chain = chain,
            staples = handshake.staples,
            cache = settings.cache,
            sources = sources,
        ).takeUnless { settings.revocation == RevocationMode.Off }
        val validator = PathValidator(
            crypto = crypto,
            anchors = anchors,
            revocation = revocation,
            limits = settings.limits,
        )
        val parameters = ValidationParameters(
            purpose = purpose,
            isRevocationRequired = settings.revocation == RevocationMode.HardFail,
        )
        val valid = when (val validation = validator.validate(chain.first(), chain.drop(1), parameters)) {
            is PathValidation.Valid -> validation
            is PathValidation.Invalid -> throw TrustRefusedException(TrustFailure.of(validation.failure))
        }
        val leaf = valid.path.first()
        refuse(handshake.isHostVerified && !matches(leaf, handshake.host), TrustFailure.HostMismatch)
        refuse(settings.pins?.matches(crypto, valid) == false, TrustFailure.PinMismatch)
        refuse(isStapleMissing(leaf, revocation), TrustFailure.MustStapleMissing)
        refuse(!isTransparent(valid, revocation), TrustFailure.TransparencyNotCompliant)
        val identity = PeerIdentity(chain = chain, path = valid.path, anchor = valid.anchor)
        refuse(!isAuthorized(identity), TrustFailure.Unauthorized)
        return identity
    }

    private fun matches(leaf: Certificate, host: String?): Boolean =
        host?.let { name -> ServiceIdentity.matches(leaf, name) } == true

    private fun isStapleMissing(leaf: Certificate, revocation: HandshakeRevocation?): Boolean {
        val isDemanded = settings.isMustStapleEnforced && STATUS_REQUEST in leaf.extensions.tlsFeatures
        return isDemanded && revocation != null && revocation.leafStaple == null
    }

    private suspend fun isTransparent(valid: PathValidation.Valid, revocation: HandshakeRevocation?): Boolean {
        val requirement = settings.transparency ?: return true
        val leaf = valid.path.first()
        val issuer = valid.path.getOrNull(1) ?: valid.anchor.certificate
        val stapled = revocation?.leafStaple?.extensions.orEmpty()
        val timestamps = stapled.firstOrNull { extension -> extension.id == OCSP_TIMESTAMPS }?.value
        val verdict = issuer?.let { found ->
            transparency.check(
                certificate = leaf,
                issuer = found,
                logs = requirement.logs,
                policy = requirement.policy,
                ocsp = timestamps,
            )
        }
        return verdict?.getOrNull()?.isCompliant == true
    }

    private suspend fun isAuthorized(identity: PeerIdentity): Boolean {
        val decider = authorizer ?: return true
        return attempted { decider.authorize(identity) }.getOrNull() == Authorization.Granted
    }

    private fun refuse(isRefused: Boolean, failure: TrustFailure) {
        if (isRefused) throw TrustRefusedException(failure)
    }

    private companion object {
        const val STATUS_REQUEST: Int = 5

        val OCSP_TIMESTAMPS: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.11129.2.4.5")

        fun contained(source: OcspResponseSource): OcspResponseSource =
            OcspResponseSource { request, certificate, issuer ->
                attempted { source.response(request, certificate, issuer) }.getOrNull()
            }

        fun contained(source: RevocationListSource): RevocationListSource = RevocationListSource { certificate ->
            attempted { source.revocationLists(certificate) }.getOrDefault(emptyList())
        }
    }
}
