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

package com.davils.krypt.acme.order

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.acme.fixture.Vectors
import com.davils.krypt.acme.fixture.crypto
import com.davils.krypt.acme.fixture.signer
import com.davils.krypt.acme.renewal.CertificateIdentifiers
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.name.GeneralName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

private const val LONGEST_TOKEN: Int = 256
private const val ADDRESS: String = "192.0.2.1"
private const val DOMAIN: String = "example.org"

private val challenges = Challenges(crypto)

private val hostileTokens = listOf(
    "short",
    "../../../../etc/passwd/aaaaaaaaaaaaaaa",
    "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-o=",
    "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-o/",
    "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-o.",
    "a".repeat(LONGEST_TOKEN + 1),
)

class ChallengesTest : FunSpec({
    test("computes the key authorization of the token of RFC 8555 with the key of RFC 8037") {
        val keys = JsonWebKeys(crypto)
        val jwk = checkNotNull(keys.decode(Vectors.RFC8037_PUBLIC).getOrNull())
        val publicKey = checkNotNull(keys.publicKey(jwk).getOrNull())
        challenges.keyAuthorization(token = Vectors.RFC8555_TOKEN, accountKey = publicKey) shouldBe
            Vectors.KEY_AUTHORIZATION
        challenges.dns01Value(Vectors.KEY_AUTHORIZATION) shouldBe Vectors.DNS01_VALUE
        val extension = challenges.tlsAlpn01Extension(Vectors.KEY_AUTHORIZATION)
        extension.id.dotted shouldBe "1.3.6.1.5.5.7.1.31"
        extension.isCritical shouldBe true
        extension.value shouldBe Vectors.hex(Vectors.ACME_IDENTIFIER_VALUE)
        challenges.http01Path(Vectors.RFC8555_TOKEN) shouldBe "/.well-known/acme-challenge/${Vectors.RFC8555_TOKEN}"
        Challenges.ALPN_PROTOCOL shouldBe "acme-tls/1"
        challenges.toString() shouldBe "Challenges"
    }

    test("computes the certificate identifier of RFC 9773") {
        val serial = checkNotNull(DerInteger.decodeOrNull(Vectors.hex(Vectors.RFC9773_SERIAL)))
        val keyIdentifier = Vectors.hex(Vectors.RFC9773_KEY_IDENTIFIER)
        CertificateIdentifiers.of(keyIdentifier = keyIdentifier, serialNumber = serial) shouldBe
            Vectors.RFC9773_IDENTIFIER
        shouldThrow<IllegalArgumentException> { CertificateIdentifiers.of(Vectors.hex(""), serial) }
        val signer = signer()
        val withoutKeyIdentifier = Certificates(crypto).issue(signer) {
            publicKey = signer.publicKey
            notBefore = crypto.environment.clock.now()
            notAfter = crypto.environment.clock.now() + 1.days
            extensions {
                val empty = Vectors.hex("3000")
                add(Extension(id = ExtensionIds.AuthorityKeyIdentifier, isCritical = false, value = empty))
            }
        }
        CertificateIdentifiers.of(withoutKeyIdentifier) shouldBe null
    }

    test("names the dns-01 record without the wildcard") {
        val name = "_acme-challenge.example.org"
        challenges.dns01Name(AcmeIdentifier.dns("*.example.org")) shouldBe name
        challenges.dns01Name(AcmeIdentifier.dns(DOMAIN)) shouldBe name
        shouldThrow<IllegalArgumentException> { challenges.dns01Name(AcmeIdentifier.ip(ADDRESS)) }
    }

    test("builds the tls-alpn-01 validation certificates of RFC 8737 and RFC 8738") {
        val dns = challenges.tlsAlpn01Certificate(
            identifier = AcmeIdentifier.dns(DOMAIN),
            keyAuthorization = Vectors.KEY_AUTHORIZATION,
            signer = signer(),
        )
        dns.extensions.subjectAlternativeNames shouldContainExactly listOf(GeneralName.Dns(DOMAIN))
        dns.extensions[Challenges.ACME_IDENTIFIER].shouldNotBeNull().value shouldBe
            Vectors.hex(Vectors.ACME_IDENTIFIER_VALUE)
        dns.notAfter - dns.notBefore shouldBe 7.days
        val ip = challenges.tlsAlpn01Certificate(
            identifier = AcmeIdentifier.ip("2001:db8::1"),
            keyAuthorization = Vectors.KEY_AUTHORIZATION,
            signer = signer(),
            validity = 1.days,
        )
        ip.extensions.subjectAlternativeNames shouldContainExactly
            listOf(checkNotNull(GeneralName.IpAddress.parseOrNull("2001:db8::1")))
        shouldThrow<IllegalArgumentException> {
            challenges.tlsAlpn01Certificate(
                identifier = AcmeIdentifier.dns("*.example.org"),
                keyAuthorization = Vectors.KEY_AUTHORIZATION,
                signer = signer(),
            )
        }
        shouldThrow<IllegalArgumentException> {
            challenges.tlsAlpn01Certificate(
                identifier = AcmeIdentifier.dns(DOMAIN),
                keyAuthorization = Vectors.KEY_AUTHORIZATION,
                signer = signer(),
                validity = Duration.ZERO,
            )
        }
    }

    test("refuses hostile tokens") {
        val publicKey = signer().publicKey
        hostileTokens.forEach { token ->
            shouldThrow<IllegalArgumentException> { challenges.http01Path(token) }
            shouldThrow<IllegalArgumentException> { challenges.keyAuthorization(token = token, accountKey = publicKey) }
        }
        val longest = "a".repeat(LONGEST_TOKEN)
        challenges.http01Path(longest) shouldBe Challenges.HTTP01_PREFIX + longest
    }
})
