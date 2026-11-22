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

import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.fixture.Authority
import com.davils.krypt.spiffe.fixture.DAYS
import com.davils.krypt.spiffe.fixture.DOMAIN_ID
import com.davils.krypt.spiffe.fixture.FOREIGN_DOMAIN_ID
import com.davils.krypt.spiffe.fixture.FOREIGN_WORKLOAD
import com.davils.krypt.spiffe.fixture.NOW
import com.davils.krypt.spiffe.fixture.WORKLOAD
import com.davils.krypt.spiffe.fixture.bundlesOf
import com.davils.krypt.spiffe.fixture.crypto
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.failure
import com.davils.krypt.spiffe.fixture.failureOf
import com.davils.krypt.spiffe.fixture.foreign
import com.davils.krypt.spiffe.fixture.idOf
import com.davils.krypt.spiffe.fixture.value
import com.davils.krypt.spiffe.fixture.workload
import com.davils.krypt.spiffe.internal.CheckedX509Svid
import com.davils.krypt.spiffe.source.BundleSource
import com.davils.krypt.x509.path.RevocationChecker
import com.davils.krypt.x509.path.RevocationStatus
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration.Companion.days

private const val OTHER_WORKLOAD: String = "spiffe://example.org/ns/prod/sa/db"
private const val HTTPS: String = "https://example.org/ca"

class X509SvidValidatorTest : FunSpec({
    test("a leaf of the bundle of its trust domain is valid, directly and through an intermediate") {
        val root = Authority.root(DOMAIN_ID)
        val validator = X509SvidValidator(crypto, bundlesOf(root.certificate))
        val leaf = root.leaf(WORKLOAD)
        val validated = validator.validate(leaf.chain).value()
        validated.id shouldBe workload
        validated.path shouldBe leaf.chain
        validated.certificate shouldBe leaf.certificate
        validated.anchor shouldBe TrustAnchor.of(root.certificate)
        validated.toString() shouldContain WORKLOAD
        val intermediate = root.intermediate(DOMAIN_ID, HTTPS)
        val deep = intermediate.leaf(OTHER_WORKLOAD)
        val chain = listOf(deep.certificate, intermediate.certificate)
        val through = validator.validate(chain).value()
        through.path shouldBe chain
        validator.toString() shouldContain "X509SvidValidator"
    }

    test("a leaf is validated only against the bundle of its own trust domain") {
        val root = Authority.root(DOMAIN_ID)
        val foreignRoot = Authority.root(FOREIGN_DOMAIN_ID)
        val own = X509SvidValidator(crypto, bundlesOf(root.certificate))
        val bundles = listOf(
            TrustBundle(domain, listOf(root.certificate)),
            TrustBundle(foreign, listOf(foreignRoot.certificate)),
        )
        val both = X509SvidValidator(crypto, BundleSet(bundles))
        val foreignLeaf = foreignRoot.leaf(FOREIGN_WORKLOAD)
        own.failureOf(foreignLeaf.chain) shouldBe X509SvidFailure.NoBundle
        val foreignId = both.idOf(foreignLeaf.chain)
        foreignId.trustDomain shouldBe foreign
        val forged = Authority.root().leaf(WORKLOAD)
        both.failureOf(forged.chain) shouldBe X509SvidFailure.Untrusted
        val impostor = foreignRoot.leaf(WORKLOAD)
        both.failureOf(impostor.chain) shouldBe X509SvidFailure.Untrusted
    }

    test("a missing, empty or failing bundle source leaves the trust domain without authorities") {
        val root = Authority.root(DOMAIN_ID)
        val leaf = root.leaf(WORKLOAD)
        X509SvidValidator(crypto, BundleSet()).failureOf(leaf.chain) shouldBe X509SvidFailure.NoBundle
        val empty = BundleSet(listOf(TrustBundle(domain)))
        X509SvidValidator(crypto, empty).failureOf(leaf.chain) shouldBe X509SvidFailure.NoBundle
        val broken = BundleSource { _ -> error("The Workload API is gone") }
        X509SvidValidator(crypto, broken).failureOf(leaf.chain) shouldBe X509SvidFailure.NoBundle
    }

    test("expiry, revocation and the length of the chain are checked") {
        val root = Authority.root(DOMAIN_ID)
        val bundles = bundlesOf(root.certificate)
        val validator = X509SvidValidator(crypto, bundles)
        val expired = root.issue(
            name = Authority.LEAF,
            notBefore = NOW - 2.days,
            notAfter = NOW - 1.days,
            extensions = Authority.leafOf(listOf(WORKLOAD)),
        )
        validator.failureOf(expired.chain) shouldBe X509SvidFailure.Expired
        val leaf = root.leaf(WORKLOAD)
        val revoked = RevocationChecker { _, _, _, _ -> RevocationStatus.Revoked }
        val checked = X509SvidValidator(crypto, bundles, revocation = revoked)
        checked.failureOf(leaf.chain) shouldBe X509SvidFailure.Revoked
        val later = ValidationParameters(at = NOW + (DAYS * 2).days)
        validator.validate(chain = leaf.chain, parameters = later).failure() shouldBe X509SvidFailure.Expired
        validator.failureOf(emptyList()) shouldBe X509SvidFailure.EmptyChain
        val intermediate = root.intermediate()
        val chain = listOf(intermediate.leaf(WORKLOAD).certificate, intermediate.certificate)
        val short = X509SvidValidator(crypto, bundles, limits = SpiffeLimits(maximumChainLength = 1))
        short.failureOf(chain) shouldBe X509SvidFailure.LimitExceeded
        validator.idOf(chain) shouldBe workload
    }

    test("signing certificates of the path and the anchor name no foreign or workload id") {
        val pathRoot = Authority.root(WORKLOAD)
        val pathLeaf = pathRoot.leaf(OTHER_WORKLOAD)
        X509SvidValidator(crypto, bundlesOf(pathRoot.certificate)).failureOf(pathLeaf.chain) shouldBe
            X509SvidFailure.SigningCertificate
        val root = Authority.root(DOMAIN_ID)
        val validator = X509SvidValidator(crypto, bundlesOf(root.certificate))
        listOf(FOREIGN_DOMAIN_ID, OTHER_WORKLOAD).forEach { uri ->
            val intermediate = root.intermediate(uri)
            val chain = listOf(intermediate.leaf(WORKLOAD).certificate, intermediate.certificate)
            validator.failureOf(chain) shouldBe X509SvidFailure.SigningCertificate
        }
        val unnamed = Authority.root()
        val unnamedLeaf = unnamed.leaf(WORKLOAD)
        X509SvidValidator(crypto, bundlesOf(unnamed.certificate)).idOf(unnamedLeaf.chain) shouldBe workload
    }

    test("validated SVIDs compare by id, path and anchor") {
        val root = Authority.root(DOMAIN_ID)
        val validator = X509SvidValidator(crypto, bundlesOf(root.certificate))
        val leaf = root.leaf(WORKLOAD)
        val first = validator.validate(leaf.chain).value()
        val second = validator.validate(leaf.chain).value()
        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
        first.equals(leaf) shouldBe false
        val other = validator.validate(root.leaf(WORKLOAD).chain).value()
        other shouldNotBe first
        val renamed = validator.validate(root.leaf(OTHER_WORKLOAD).chain).value()
        renamed shouldNotBe first
        val otherRoot = Authority.root(DOMAIN_ID)
        val rebased = X509SvidValidator(crypto, bundlesOf(otherRoot.certificate, root.certificate))
        val anchor = TrustAnchor.of(otherRoot.certificate)
        val reanchored = ValidatedX509Svid(CheckedX509Svid(id = first.id, path = first.path, anchor = anchor))
        reanchored shouldNotBe first
        rebased.validate(leaf.chain).value() shouldBe first
    }
})
