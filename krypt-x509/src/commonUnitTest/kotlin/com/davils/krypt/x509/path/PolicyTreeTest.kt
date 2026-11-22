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

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.der
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val HOST: String = "api.example.com"
private const val NODES: Int = 2
private val FIRST: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.1")
private val SECOND: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.4.1.99999.2")
private val ANY: ObjectIdentifier = KeyPurposes.AnyPolicy
private val FIRST_TO_SECOND: Extension = mapping(from = FIRST, to = SECOND)

private fun mapping(from: ObjectIdentifier, to: ObjectIdentifier): Extension = Extension(
    ExtensionIds.PolicyMappings,
    true,
    der {
        sequence {
            sequence {
                objectIdentifier(from)
                objectIdentifier(to)
            }
        }
    },
)

private suspend fun chain(
    authorityPolicies: List<ObjectIdentifier>,
    leafPolicies: List<ObjectIdentifier>?,
    mapped: Extension? = null,
): PolicyChain {
    val root = Authority.root()
    val authority = root.issue("authority", isCa = true, extensions = {
        basicConstraints(isCa = true)
        keyUsage(setOf(KeyUsage.KeyCertSign))
        certificatePolicies(authorityPolicies)
        mapped?.let { extension -> add(extension) }
    })
    val leaf = authority.issue(HOST, extensions = {
        basicConstraints(isCa = false)
        leafPolicies?.let { policies -> certificatePolicies(policies) }
    })
    return PolicyChain(root, authority, leaf)
}

private fun failureOf(result: PathValidation): PathFailure? = (result as? PathValidation.Invalid)?.failure

private fun policiesOf(result: PathValidation): Set<ObjectIdentifier>? = (result as? PathValidation.Valid)?.policies

class PolicyTreeTest : FunSpec({
    test("a user policy is compared in the domain of the anchor, as the policy tree of RFC 5280 does") {
        val mapped = chain(authorityPolicies = listOf(FIRST), leafPolicies = listOf(SECOND), mapped = FIRST_TO_SECOND)
        failureOf(mapped.validate(initial = setOf(SECOND))) shouldBe PathFailure.Policy
        policiesOf(mapped.validate(initial = setOf(FIRST))) shouldBe setOf(SECOND)
        policiesOf(mapped.validate()) shouldBe setOf(SECOND)
    }

    test("an inhibited mapping deletes the mapped policy") {
        val mapped = chain(authorityPolicies = listOf(FIRST), leafPolicies = listOf(SECOND), mapped = FIRST_TO_SECOND)
        failureOf(mapped.validate(isMappingInhibited = true)) shouldBe PathFailure.Policy
        policiesOf(mapped.validate(isMappingInhibited = true, isExplicit = false)) shouldBe emptySet()
    }

    test("a mapping of anyPolicy creates the issuer policy next to it") {
        val mapped = chain(authorityPolicies = listOf(ANY), leafPolicies = listOf(SECOND), mapped = FIRST_TO_SECOND)
        policiesOf(mapped.validate(initial = setOf(FIRST))) shouldBe setOf(SECOND)
    }

    test("named policies next to anyPolicy are kept") {
        val both = chain(authorityPolicies = listOf(FIRST, ANY), leafPolicies = listOf(FIRST))
        policiesOf(both.validate(initial = setOf(FIRST))) shouldBe setOf(FIRST)
        val other = chain(authorityPolicies = listOf(FIRST, ANY), leafPolicies = listOf(SECOND))
        policiesOf(other.validate(initial = setOf(SECOND))) shouldBe setOf(SECOND)
        failureOf(other.validate(initial = setOf(SECOND), isAnyInhibited = true)) shouldBe PathFailure.Policy
    }

    test("anyPolicy at the end entity stands for the user policies") {
        val open = chain(authorityPolicies = listOf(ANY), leafPolicies = listOf(ANY))
        policiesOf(open.validate(initial = setOf(FIRST))) shouldBe setOf(FIRST)
        policiesOf(open.validate()) shouldBe setOf(ANY)
        failureOf(open.validate(initial = setOf(FIRST), isAnyInhibited = true)) shouldBe PathFailure.Policy
    }

    test("an end entity without policies is valid for none") {
        val bare = chain(authorityPolicies = listOf(FIRST), leafPolicies = null)
        failureOf(bare.validate()) shouldBe PathFailure.Policy
        policiesOf(bare.validate(isExplicit = false)) shouldBe emptySet()
    }

    test("the policy tree is bounded") {
        val plain = chain(authorityPolicies = listOf(FIRST), leafPolicies = listOf(FIRST))
        policiesOf(plain.validate()) shouldBe setOf(FIRST)
        val narrow = X509Limits(maximumPolicyNodes = NODES)
        failureOf(plain.validate(limits = narrow, isExplicit = false)) shouldBe PathFailure.Policy
    }
})
