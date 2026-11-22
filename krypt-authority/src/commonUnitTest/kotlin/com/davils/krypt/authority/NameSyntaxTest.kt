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

package com.davils.krypt.authority

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.policy.issuancePolicy
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val DOMAIN: String = "example.com"
private const val SPIFFE: String = "spiffe://example.org"
private const val LONG_LABEL: Int = 64
private const val LONG_NAME_LABELS: Int = 64

private suspend fun failureOf(name: GeneralName, policy: IssuancePolicy): IssuanceFailure? {
    val authority = rootAuthority(policy = policy).authority
    val profiles = listOf(CertificateProfile.TlsServer, CertificateProfile.SpiffeSvid)
    val profile = profiles[(name is GeneralName.Uri).compareTo(false)]
    return authority.issue(serverRequest(name = name, profile = profile)).failureOrNull()
}

private suspend fun dns(name: String, policy: IssuancePolicy): IssuanceFailure? =
    failureOf(name = GeneralName.Dns(name), policy = policy)

class NameSyntaxTest : FunSpec({
    test("a partial wildcard is refused when wildcards are not allowed") {
        val policy = issuancePolicy { dnsDomains(DOMAIN) }
        dns(name = "f*.example.com", policy = policy) shouldBe IssuanceFailure.NameNotPermitted
        dns(name = "a.*.example.com", policy = policy) shouldBe IssuanceFailure.NameNotPermitted
        dns(name = "*.example.com", policy = policy) shouldBe IssuanceFailure.NameNotPermitted
    }

    test("a wildcard is a whole leftmost label before at least two labels") {
        val policy = issuancePolicy { isWildcardAllowed = true }
        dns(name = "*.example.com", policy = policy) shouldBe null
        dns(name = "*.com", policy = policy) shouldBe IssuanceFailure.NameNotPermitted
        dns(name = "f*.example.com", policy = policy) shouldBe IssuanceFailure.NameNotPermitted
        dns(name = "*", policy = policy) shouldBe IssuanceFailure.NameNotPermitted
    }

    test("DNS names are letters, digits and hyphens in labels of bounded length") {
        val open = IssuancePolicy.Default
        dns(name = "api-1.example.com", policy = open) shouldBe null
        dns(name = "under_score.example.com", policy = open) shouldBe IssuanceFailure.NameNotPermitted
        dns(name = "-lead.example.com", policy = open) shouldBe IssuanceFailure.NameNotPermitted
        dns(name = "trail-.example.com", policy = open) shouldBe IssuanceFailure.NameNotPermitted
        dns(name = "example.com.", policy = open) shouldBe IssuanceFailure.NameNotPermitted
        dns(name = "a".repeat(LONG_LABEL) + ".com", policy = open) shouldBe IssuanceFailure.NameNotPermitted
        val long = List(LONG_NAME_LABELS) { "abc" }.joinToString(".")
        dns(name = long, policy = open) shouldBe IssuanceFailure.NameNotPermitted
    }

    test("a URI prefix matches only at a slash or as the whole URI") {
        val bare = issuancePolicy { uriPrefixes(SPIFFE) }
        failureOf(GeneralName.Uri("$SPIFFE/web"), bare) shouldBe null
        failureOf(GeneralName.Uri(SPIFFE), bare) shouldBe null
        failureOf(GeneralName.Uri("$SPIFFE.evil/web"), bare) shouldBe IssuanceFailure.NameNotPermitted
        val slashed = issuancePolicy { uriPrefixes("$SPIFFE/") }
        failureOf(GeneralName.Uri("$SPIFFE/web"), slashed) shouldBe null
        failureOf(GeneralName.Uri("${SPIFFE}x/web"), slashed) shouldBe IssuanceFailure.NameNotPermitted
    }
})
