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

package com.davils.krypt.tls.fixture

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.authority.CertificateAuthority
import com.davils.krypt.authority.IssuanceRequest
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.keystore.Identities
import com.davils.krypt.keystore.Identity
import com.davils.krypt.ocsp.Ocsp
import com.davils.krypt.ocsp.OcspIssuer
import com.davils.krypt.ocsp.OcspResponder
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.crl.RevocationList
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.distinguishedName
import com.davils.krypt.x509.path.TrustAnchor
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

internal class Pki private constructor(
    val authority: CertificateAuthority,
    val signer: Signer,
    private val parents: List<Certificate>,
) {
    val certificate: Certificate get() = authority.certificate

    val anchor: TrustAnchor get() = TrustAnchor.of(certificate)

    suspend fun identity(profile: CertificateProfile, vararg names: GeneralName): Identity {
        val pair = crypto.keys.generate(KeyType.P256)
        val request = IssuanceRequest(
            subject = distinguishedName {
                organization(LEAF)
                if (names.isEmpty()) commonName(LEAF)
            },
            publicKey = pair.publicKey,
            profile = profile,
            names = names.toList(),
            validity = DAYS.days,
        )
        val outcome = authority.issue(request)
        val issued = checkNotNull(outcome.getOrNull()) { "The authority refused the request: $outcome" }
        return identityOf(pair.privateKey, listOf(issued) + parents)
    }

    suspend fun custom(names: List<GeneralName>, extensions: ExtensionsBuilder.() -> Unit = {}): Identity {
        val pair = crypto.keys.generate(KeyType.P256)
        val now = crypto.environment.clock.now()
        val issued = Certificates(crypto).issue(signer) {
            subject { commonName(LEAF) }
            issuer = certificate.subject
            publicKey = pair.publicKey
            notBefore = now - 1.hours
            notAfter = now + DAYS.days
            extensions {
                keyUsage(setOf(KeyUsage.DigitalSignature))
                subjectAlternativeNames(names)
                authorityKeyIdentifier(checkNotNull(certificate.extensions.subjectKeyIdentifier))
                extensions()
            }
        }
        authority.repository.record(issued)
        return identityOf(pair.privateKey, listOf(issued) + parents)
    }

    suspend fun intermediate(name: String = INTERMEDIATE): Pki {
        val pair = crypto.keys.generate(KeyType.P256)
        val request = IssuanceRequest(
            subject = distinguishedName { commonName(name) },
            publicKey = pair.publicKey,
            profile = CertificateProfile.intermediate(),
            validity = INTERMEDIATE_DAYS.days,
        )
        val issued = checkNotNull(authority.issue(request).getOrNull()) { "The authority refused the intermediate" }
        val signer = crypto.signatures.signer(pair.privateKey)
        val authority = CertificateAuthority(
            crypto = crypto,
            certificate = issued,
            signer = signer,
            repository = MemoryRepository(),
        )
        return Pki(authority = authority, signer = signer, parents = listOf(issued) + parents)
    }

    suspend fun revoke(identity: Identity) {
        checkNotNull(authority.revoke(identity.certificate.serialNumber).getOrNull()) { "The revocation was refused" }
    }

    suspend fun revocationList(): RevocationList = authority.revocationList()

    suspend fun revocationList(validity: Duration): RevocationList = authority.revocationList(validity)

    fun responder(): OcspResponder = OcspResponder(
        ocsp = Ocsp(crypto),
        issuer = OcspIssuer.of(certificate),
        signer = signer,
        source = authority.statusSource,
    )

    companion object {
        suspend fun create(name: String = ROOT): Pki {
            val pair = crypto.keys.generate(KeyType.P256)
            val signer = crypto.signatures.signer(pair.privateKey)
            val root = CertificateAuthority.createRoot(
                crypto = crypto,
                signer = signer,
                subject = distinguishedName { commonName(name) },
                validity = (DAYS * 2).days,
            )
            val authority = CertificateAuthority(
                crypto = crypto,
                certificate = root,
                signer = signer,
                repository = MemoryRepository(),
            )
            return Pki(authority = authority, signer = signer, parents = emptyList())
        }

        suspend fun identityOf(key: PrivateKey, chain: List<Certificate>): Identity {
            val identity = Identities(crypto).of(key, chain)
            return checkNotNull(identity.getOrNull()) { "The key does not fit" }
        }
    }
}
