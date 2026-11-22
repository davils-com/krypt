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

package com.davils.krypt.x509.path

import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val HOST: String = "api.example.com"
private const val WILDCARD: String = "*.example.com"
private const val SECRET: String = "secret.example.com"

private suspend fun accepts(constraints: NameConstraints, name: GeneralName): Boolean {
    val root = Authority.root()
    val constrained = root.issue("constrained", isCa = true, extensions = {
        basicConstraints(isCa = true)
        keyUsage(setOf(KeyUsage.KeyCertSign))
        nameConstraints(constraints)
    })
    val leaf = constrained
        .issue(HOST, extensions = {
            basicConstraints(isCa = false)
            subjectAlternativeNames(listOf(name))
        })
        .certificate
    val validator = PathValidator(crypto = crypto, anchors = listOf(TrustAnchor.of(root.certificate)))
    return validator.validate(leaf, listOf(constrained.certificate), ValidationParameters(at = NOW)).isValid
}

private suspend fun excluding(base: String, name: String): Boolean =
    accepts(NameConstraints(excluded = listOf(GeneralName.Dns(base))), GeneralName.Dns(name))

private suspend fun permitting(base: String, name: String): Boolean =
    accepts(NameConstraints(permitted = listOf(GeneralName.Dns(base))), GeneralName.Dns(name))

class NameScopeTest : FunSpec({
    test("a wildcard does not carry a certificate into an excluded subtree") {
        excluding(base = SECRET, name = WILDCARD) shouldBe false
        excluding(base = "SECRET.Example.COM.", name = WILDCARD) shouldBe false
        excluding(base = "example.com", name = WILDCARD) shouldBe false
        excluding(base = ".example.com", name = WILDCARD) shouldBe false
        excluding(base = "", name = WILDCARD) shouldBe false
        excluding(base = ".secret.example.com", name = WILDCARD) shouldBe true
        excluding(base = "a.secret.example.com", name = WILDCARD) shouldBe true
        excluding(base = "secret.example.org", name = WILDCARD) shouldBe true
        excluding(base = SECRET, name = HOST) shouldBe true
    }

    test("a wildcard is permitted only if its whole scope is") {
        permitting(base = "example.com", name = WILDCARD) shouldBe true
        permitting(base = ".example.com", name = WILDCARD) shouldBe true
        permitting(base = "com", name = WILDCARD) shouldBe true
        permitting(base = "", name = WILDCARD) shouldBe true
        permitting(base = SECRET, name = WILDCARD) shouldBe false
        permitting(base = ".api.example.com", name = WILDCARD) shouldBe false
        permitting(base = "example.com.", name = "API.Example.com.") shouldBe true
    }

    test("a URI with a trailing dot stays in its excluded subtree") {
        val evil = NameConstraints(excluded = listOf(GeneralName.Uri("evil.com")))
        accepts(evil, GeneralName.Uri("https://evil.com./login")) shouldBe false
        accepts(evil, GeneralName.Uri("https://EVIL.com/login")) shouldBe false
        accepts(evil, GeneralName.Uri("https://good.com/login")) shouldBe true
        val below = NameConstraints(excluded = listOf(GeneralName.Uri(".evil.com.")))
        accepts(below, GeneralName.Uri("https://www.evil.com./")) shouldBe false
    }
})
