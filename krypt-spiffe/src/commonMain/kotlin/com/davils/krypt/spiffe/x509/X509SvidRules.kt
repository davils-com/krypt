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

package com.davils.krypt.spiffe.x509

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.getOrNull
import com.davils.kore.core.outcome.mapFailure
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.GeneralName

/**
 * The structural rules of the X509-SVID specification, without path validation.
 *
 * A leaf names exactly one URI, which is a SPIFFE id with a path; it is no authority, and its key usage is critical,
 * names `digitalSignature` and names neither `keyCertSign` nor `cRLSign`. A signing certificate is an authority with
 * `keyCertSign`; every `spiffe:` URI it names is the id of the trust domain of the leaf, without a path, which is
 * stricter than the SHOULD of section 3.2.
 *
 * The object holds no state and is safe to share between threads.
 *
 * @since 1.0.0
 */
public object X509SvidRules {
    private const val SCHEME: String = "spiffe:"

    private val AUTHORITY_USAGES: Set<KeyUsage> = setOf(KeyUsage.KeyCertSign, KeyUsage.CrlSign)

    /**
     * Checks [certificate] as the leaf of an X.509-SVID and reads its SPIFFE id.
     *
     * @param certificate the leaf, possibly from an attacker.
     * @return the SPIFFE id, or the rule the leaf breaks.
     * @since 1.0.0
     */
    public fun leaf(certificate: Certificate): Outcome<SpiffeId, X509SvidFailure> {
        val uris = urisOf(certificate)
        val failure = X509SvidFailure.NoSpiffeId.takeIf { uris.isEmpty() }
            ?: X509SvidFailure.SeveralUris.takeIf { uris.size > 1 }
        if (failure != null) return Outcome.Failure(failure)
        val parsed = SpiffeId.parse(uris.single().uri).mapFailure { _ -> X509SvidFailure.InvalidSpiffeId }
        return parsed.flatMap { id -> outcomeOf(value = id, failure = leafFailure(certificate = certificate, id = id)) }
    }

    /**
     * Checks a path: the first certificate as the leaf, every other one as a signing certificate.
     *
     * @param path the leaf first, then its issuers, possibly with the certificate of the trust anchor last.
     * @return the SPIFFE id of the leaf, or the first rule a certificate breaks.
     * @since 1.0.0
     */
    public fun path(path: List<Certificate>): Outcome<SpiffeId, X509SvidFailure> {
        if (path.isEmpty()) return Outcome.Failure(X509SvidFailure.EmptyChain)
        return leaf(path.first()).flatMap { id ->
            val isSigned = path.drop(1).all { certificate -> isSigning(certificate, id.trustDomain) }
            outcomeOf(value = id, failure = X509SvidFailure.SigningCertificate.takeUnless { isSigned })
        }
    }

    private fun leafFailure(certificate: Certificate, id: SpiffeId): X509SvidFailure? =
        X509SvidFailure.TrustDomainId.takeIf { id.isTrustDomainId }
            ?: X509SvidFailure.CertificateAuthority.takeIf { certificate.isCa }
            ?: X509SvidFailure.KeyUsage.takeUnless { isLeafUsage(certificate) }

    private fun isLeafUsage(certificate: Certificate): Boolean {
        val extensions = certificate.extensions
        val isCritical = extensions[ExtensionIds.KeyUsage]?.isCritical == true
        val usages = extensions.keyUsage.orEmpty()
        return isCritical && KeyUsage.DigitalSignature in usages && usages.none { usage -> usage in AUTHORITY_USAGES }
    }

    private fun isSigning(certificate: Certificate, trustDomain: TrustDomain): Boolean {
        val extensions = certificate.extensions
        val usages = extensions.keyUsage.orEmpty()
        val ids = urisOf(certificate).filter { name -> name.uri.startsWith(SCHEME) }
        val isNamed = ids.all { name -> isAuthorityId(uri = name.uri, trustDomain = trustDomain) }
        return certificate.isCa && KeyUsage.KeyCertSign in usages && isNamed
    }

    private fun isAuthorityId(uri: String, trustDomain: TrustDomain): Boolean {
        val id = SpiffeId.parse(uri).getOrNull()
        return id != null && id.isTrustDomainId && id.memberOf(trustDomain)
    }

    private fun urisOf(certificate: Certificate): List<GeneralName.Uri> {
        val names = certificate.extensions.subjectAlternativeNames
        return names.filterIsInstance<GeneralName.Uri>()
    }

    private fun <T> outcomeOf(value: T, failure: X509SvidFailure?): Outcome<T, X509SvidFailure> {
        if (failure != null) return Outcome.Failure(failure)
        return Outcome.Success(value)
    }
}
