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

package com.davils.krypt.tls.peer

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.source.BundleSource
import com.davils.krypt.tls.ClientAuthentication
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.fixture.FOREIGN_ID
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.SPIFFE_ID
import com.davils.krypt.tls.fixture.clientConfiguration
import com.davils.krypt.tls.fixture.connect
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.internal.CheckedPeer
import com.davils.krypt.tls.trust.TrustFailure
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.name.GeneralName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private const val DOMAIN: String = "example.org"
private const val FOREIGN: String = "example.com"

private val CLIENT: ExtensionsBuilder.() -> Unit = { extendedKeyUsage(listOf(KeyPurposes.ClientAuth)) }

private fun idOf(text: String): SpiffeId = SpiffeId.parse(text).getOrNull() ?: error("id")

private suspend fun peer(
    pki: Pki,
    vararg names: GeneralName,
    extensions: ExtensionsBuilder.() -> Unit = CLIENT,
): PeerIdentity {
    val identity = pki.custom(names.toList(), extensions)
    return PeerIdentity(CheckedPeer(chain = identity.chain, path = identity.chain, anchor = pki.anchor))
}

private fun bundlesOf(pki: Pki): BundleSet =
    BundleSet(listOf(TrustBundle(TrustDomain.of(DOMAIN), x509Authorities = listOf(pki.certificate))))

class SpiffeAuthorizerTest : FunSpec({
    test("ids are allowed exactly and trust domains as a whole") {
        val pki = Pki.create()
        val inside = peer(pki, GeneralName.Uri(SPIFFE_ID))
        val outside = peer(pki, GeneralName.Uri(FOREIGN_ID))
        val exact = SpiffeAuthorizer.ids(idOf(SPIFFE_ID))
        exact.authorize(inside) shouldBe Authorization.Granted
        exact.authorize(outside) shouldBe Authorization.Denied
        exact.ids shouldBe setOf(idOf(SPIFFE_ID))
        val domains = SpiffeAuthorizer.trustDomains(TrustDomain.of(FOREIGN))
        domains.authorize(outside) shouldBe Authorization.Granted
        domains.authorize(inside) shouldBe Authorization.Denied
        domains.trustDomains shouldBe setOf(TrustDomain.of(FOREIGN))
        domains.toString() shouldContain "trustDomains=1"
    }

    test("a predicate decides about the id, and a failing one denies") {
        val pki = Pki.create()
        val inside = peer(pki, GeneralName.Uri(SPIFFE_ID))
        SpiffeAuthorizer.matching { id -> id.segments.first() == "ns" }.authorize(inside) shouldBe Authorization.Granted
        SpiffeAuthorizer.matching { false }.authorize(inside) shouldBe Authorization.Denied
        SpiffeAuthorizer.matching { error("The predicate broke") }.authorize(inside) shouldBe Authorization.Denied
    }

    test("a peer without an X.509-SVID is denied whatever its names") {
        val pki = Pki.create()
        val everyone = SpiffeAuthorizer.matching { true }
        everyone.authorize(peer(pki, GeneralName.Dns("api.example.org"))) shouldBe Authorization.Denied
        val twice = peer(pki, GeneralName.Uri(SPIFFE_ID), GeneralName.Uri(FOREIGN_ID))
        everyone.authorize(twice) shouldBe Authorization.Denied
        everyone.authorize(peer(pki, GeneralName.Uri("spiffe://example.org"))) shouldBe Authorization.Denied
        val authority = peer(pki, GeneralName.Uri(SPIFFE_ID)) {
            extendedKeyUsage(listOf(KeyPurposes.ClientAuth))
            basicConstraints(isCa = true)
        }
        everyone.authorize(authority) shouldBe Authorization.Denied
        everyone.authorize(peer(pki, GeneralName.Uri(SPIFFE_ID))) shouldBe Authorization.Granted
    }

    test("with bundles, the anchor of the peer must be an X.509 authority of its trust domain") {
        val pki = Pki.create()
        val other = Pki.create()
        val inside = peer(pki, GeneralName.Uri(SPIFFE_ID))
        val domain = TrustDomain.of(DOMAIN)
        SpiffeAuthorizer.trustDomains(domain, bundles = bundlesOf(pki)).authorize(inside) shouldBe Authorization.Granted
        SpiffeAuthorizer.trustDomains(domain, bundles = bundlesOf(other)).authorize(inside) shouldBe
            Authorization.Denied
        SpiffeAuthorizer.trustDomains(domain, bundles = BundleSet()).authorize(inside) shouldBe Authorization.Denied
        val broken = BundleSource { _ -> error("The Workload API is gone") }
        SpiffeAuthorizer.ids(idOf(SPIFFE_ID), bundles = broken).authorize(inside) shouldBe Authorization.Denied
        val foreignInside = peer(pki, GeneralName.Uri(FOREIGN_ID))
        val federated = SpiffeAuthorizer.matching(bundles = bundlesOf(pki)) { true }
        federated.authorize(foreignInside) shouldBe Authorization.Denied
        federated.toString() shouldContain "bundles=true"
    }

    test("an authorizer names at least one and at most the maximum of rules") {
        shouldThrow<IllegalArgumentException> { SpiffeAuthorizer.ids() }
        shouldThrow<IllegalArgumentException> { SpiffeAuthorizer.trustDomains() }
        val many = Array(PeerPolicy.HARD_MAXIMUM_RULES + 1) { index -> TrustDomain.of("d$index") }
        shouldThrow<IllegalArgumentException> { SpiffeAuthorizer.trustDomains(trustDomains = many) }
        val most = Array(PeerPolicy.HARD_MAXIMUM_RULES) { index -> TrustDomain.of("d$index") }
        val bounded = SpiffeAuthorizer.trustDomains(trustDomains = most)
        bounded.trustDomains.size shouldBe PeerPolicy.HARD_MAXIMUM_RULES
    }

    test("a server admits only clients of the allowed trust domain anchored in its bundle") {
        val pki = Pki.create()
        val server = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val authorizer = SpiffeAuthorizer.trustDomains(TrustDomain.of(DOMAIN), bundles = bundlesOf(pki))
        val serverContext = TlsContext(
            serverConfiguration(pki, listOf(server)) {
                clientAuthentication = ClientAuthentication.Required
                this.authorizer = authorizer
            },
        )
        val admitted = pki.custom(listOf(GeneralName.Uri(SPIFFE_ID)), CLIENT)
        val admittedClient = TlsContext(clientConfiguration(pki) { identities = listOf(admitted) })
        connect(client = admittedClient, server = serverContext).isEstablished shouldBe true
        val refused = pki.custom(listOf(GeneralName.Uri(FOREIGN_ID)), CLIENT)
        val refusedClient = TlsContext(clientConfiguration(pki) { identities = listOf(refused) })
        val failures = connect(client = refusedClient, server = serverContext).failures
        failures.firstNotNullOfOrNull { failure -> TrustFailure.of(failure) } shouldBe TrustFailure.Unauthorized
    }
})
