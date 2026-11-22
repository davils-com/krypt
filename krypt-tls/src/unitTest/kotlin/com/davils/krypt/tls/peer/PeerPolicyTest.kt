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

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.tls.fixture.FOREIGN_ID
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SPIFFE_DOMAIN
import com.davils.krypt.tls.fixture.SPIFFE_ID
import com.davils.krypt.tls.fixture.StubSession
import com.davils.krypt.tls.internal.CheckedPeer
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.name.GeneralName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private const val DOMAIN: String = "example.org"
private const val API_HOST: String = "api.example.org"
private const val MAIL: String = "ops@Example.org"

private suspend fun peer(pki: Pki, vararg names: GeneralName): PeerIdentity {
    val identity = pki.custom(names.toList()) { extendedKeyUsage(listOf(KeyPurposes.ClientAuth)) }
    return PeerIdentity(CheckedPeer(chain = identity.chain, path = identity.chain, anchor = pki.anchor))
}

class PeerPolicyTest : FunSpec({
    test("URIs match exactly or by a prefix that ends with a slash") {
        val pki = Pki.create()
        val inside = peer(pki, GeneralName.Uri(SPIFFE_ID))
        val outside = peer(pki, GeneralName.Uri(FOREIGN_ID))
        peerPolicy { uriPrefix(SPIFFE_DOMAIN) }.authorize(inside) shouldBe Authorization.Granted
        peerPolicy { uriPrefix(SPIFFE_DOMAIN) }.authorize(outside) shouldBe Authorization.Denied
        peerPolicy { uri(FOREIGN_ID) }.authorize(outside) shouldBe Authorization.Granted
        peerPolicy { uri(FOREIGN_ID) }.authorize(inside) shouldBe Authorization.Denied
        peerPolicy {}.authorize(outside) shouldBe Authorization.Granted
    }

    test("DNS names and email addresses match exactly or by domain") {
        val pki = Pki.create()
        val host = peer(pki, GeneralName.Dns("API.example.org."))
        val mail = peer(pki, GeneralName.Email(MAIL))
        val address = peer(pki, GeneralName.IpAddress.parseOrNull("10.0.0.1") ?: error("address"))
        peerPolicy { dns(API_HOST) }.authorize(host) shouldBe Authorization.Granted
        peerPolicy { dnsDomain(DOMAIN) }.authorize(host) shouldBe Authorization.Granted
        peerPolicy { dnsDomain("pi.example.org") }.authorize(host) shouldBe Authorization.Denied
        peerPolicy { email("ops@example.org") }.authorize(mail) shouldBe Authorization.Granted
        peerPolicy { emailDomain("EXAMPLE.org") }.authorize(mail) shouldBe Authorization.Granted
        peerPolicy { emailDomain("example.com") }.authorize(mail) shouldBe Authorization.Denied
        peerPolicy { dns(API_HOST) }.authorize(mail) shouldBe Authorization.Denied
        peerPolicy { email(MAIL) }.authorize(address) shouldBe Authorization.Denied
    }

    test("purposes and the predicate are further conditions, and a failing predicate denies") {
        val pki = Pki.create()
        val client = peer(pki, GeneralName.Uri(SPIFFE_ID))
        peerPolicy { purpose(KeyPurposes.ClientAuth) }.authorize(client) shouldBe Authorization.Granted
        peerPolicy { purpose(KeyPurposes.ServerAuth) }.authorize(client) shouldBe Authorization.Denied
        peerPolicy { require { found -> found.uris == listOf(SPIFFE_ID) } }.authorize(client) shouldBe
            Authorization.Granted
        peerPolicy { require { false } }.authorize(client) shouldBe Authorization.Denied
        peerPolicy { require { error("The predicate broke") } }.authorize(client) shouldBe Authorization.Denied
        val policy = peerPolicy {
            uriPrefix(SPIFFE_DOMAIN)
            purpose(KeyPurposes.ClientAuth)
        }
        policy.uriPrefixes shouldBe listOf(SPIFFE_DOMAIN)
        policy.uris shouldBe emptyList()
        policy.dnsNames shouldBe emptyList()
        policy.dnsDomains shouldBe emptyList()
        policy.emails shouldBe emptyList()
        policy.emailDomains shouldBe emptyList()
        policy.purposes shouldBe listOf(KeyPurposes.ClientAuth)
        policy.toString() shouldContain "rules=1"
    }

    test("rules are checked when the policy is built") {
        shouldThrow<ValidationException> { peerPolicy { uriPrefix("spiffe://example.org") } }
        shouldThrow<ValidationException> { peerPolicy { uriPrefix("example.org/") } }
        shouldThrow<ValidationException> { peerPolicy { dns(" ") } }
        shouldThrow<ValidationException> { peerPolicy { email("a".repeat(PeerPolicy.HARD_MAXIMUM_LENGTH + 1)) } }
        shouldThrow<ValidationException> {
            peerPolicy { repeat(PeerPolicy.HARD_MAXIMUM_RULES + 1) { uri(SPIFFE_ID) } }
        }
        shouldThrow<ValidationException> {
            peerPolicy { repeat(PeerPolicy.HARD_MAXIMUM_RULES + 1) { purpose(KeyPurposes.ClientAuth) } }
        }
    }

    test("a peer identity compares by chain, path and anchor and is read from the session") {
        val pki = Pki.create()
        val other = Pki.create("Other")
        val first = peer(pki, GeneralName.Uri(SPIFFE_ID))
        val second = peer(pki, GeneralName.Uri(SPIFFE_ID))
        val same = PeerIdentity(CheckedPeer(chain = first.chain, path = first.path, anchor = first.anchor))
        first shouldBe same
        first.hashCode() shouldBe same.hashCode()
        (first == second) shouldBe false
        val otherPath = PeerIdentity(CheckedPeer(chain = first.chain, path = second.path, anchor = first.anchor))
        (first == otherPath) shouldBe false
        val otherAnchor = PeerIdentity(CheckedPeer(chain = first.chain, path = first.path, anchor = other.anchor))
        (first == otherAnchor) shouldBe false
        first.equals(SPIFFE_ID) shouldBe false
        first.toString() shouldContain "PeerIdentity"
        PeerIdentity.of(StubSession(emptyList())).shouldBeNull()
    }
})
