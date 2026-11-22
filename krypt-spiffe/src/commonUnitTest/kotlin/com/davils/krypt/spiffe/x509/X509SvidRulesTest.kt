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

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.fixture.Authority
import com.davils.krypt.spiffe.fixture.DOMAIN
import com.davils.krypt.spiffe.fixture.DOMAIN_ID
import com.davils.krypt.spiffe.fixture.FOREIGN_WORKLOAD
import com.davils.krypt.spiffe.fixture.WORKLOAD
import com.davils.krypt.spiffe.fixture.crypto
import com.davils.krypt.spiffe.fixture.failure
import com.davils.krypt.spiffe.fixture.value
import com.davils.krypt.spiffe.fixture.workload
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

private const val HINT: String = "internal"

private suspend fun leafFailure(root: Authority, extensions: ExtensionsBuilder.() -> Unit): X509SvidFailure? {
    val leaf = root.issue(name = Authority.LEAF, extensions = extensions)
    return X509SvidRules.leaf(leaf.certificate).failure()
}

class X509SvidRulesTest : FunSpec({
    test("a leaf names exactly one URI, which is a SPIFFE id with a path") {
        val root = Authority.root(DOMAIN_ID)
        X509SvidRules.leaf(root.leaf(WORKLOAD).certificate).value() shouldBe workload
        leafFailure(root, Authority.leafOf(emptyList())) shouldBe X509SvidFailure.NoSpiffeId
        val dnsOnly: ExtensionsBuilder.() -> Unit = {
            Authority.leafOf(emptyList())()
            subjectAlternativeNames(listOf(GeneralName.Dns(DOMAIN)))
        }
        leafFailure(root, dnsOnly) shouldBe X509SvidFailure.NoSpiffeId
        leafFailure(root, Authority.leafOf(listOf(WORKLOAD, FOREIGN_WORKLOAD))) shouldBe X509SvidFailure.SeveralUris
        leafFailure(root, Authority.leafOf(listOf("https://example.org/api"))) shouldBe
            X509SvidFailure.InvalidSpiffeId
        leafFailure(root, Authority.leafOf(listOf("spiffe://example.org/"))) shouldBe X509SvidFailure.InvalidSpiffeId
        leafFailure(root, Authority.leafOf(listOf(DOMAIN_ID))) shouldBe X509SvidFailure.TrustDomainId
        val withDns: ExtensionsBuilder.() -> Unit = {
            Authority.leafOf(emptyList())()
            subjectAlternativeNames(listOf(GeneralName.Uri(WORKLOAD), GeneralName.Dns(DOMAIN)))
        }
        X509SvidRules.leaf(root.issue(name = Authority.LEAF, extensions = withDns).certificate).value() shouldBe
            workload
    }

    test("a leaf is no authority and its critical key usage signs but never certifies") {
        val root = Authority.root(DOMAIN_ID)
        leafFailure(root, Authority.signingOf(listOf(WORKLOAD))) shouldBe X509SvidFailure.CertificateAuthority
        val unused: ExtensionsBuilder.() -> Unit = {
            basicConstraints(isCa = false)
            subjectAlternativeNames(listOf(GeneralName.Uri(WORKLOAD)))
        }
        leafFailure(root, unused) shouldBe X509SvidFailure.KeyUsage
        val lax: ExtensionsBuilder.() -> Unit = {
            keyUsage(setOf(KeyUsage.DigitalSignature), critical = false)
            subjectAlternativeNames(listOf(GeneralName.Uri(WORKLOAD)))
        }
        leafFailure(root, lax) shouldBe X509SvidFailure.KeyUsage
        val usages = listOf(
            setOf(KeyUsage.KeyAgreement),
            setOf(KeyUsage.DigitalSignature, KeyUsage.KeyCertSign),
            setOf(KeyUsage.DigitalSignature, KeyUsage.CrlSign),
        )
        usages.forEach { set ->
            leafFailure(root, Authority.leafOf(listOf(WORKLOAD), set)) shouldBe X509SvidFailure.KeyUsage
        }
        val agreeing = Authority.leafOf(listOf(WORKLOAD), setOf(KeyUsage.DigitalSignature, KeyUsage.KeyAgreement))
        leafFailure(root, agreeing) shouldBe null
    }

    test("signing certificates are authorities with keyCertSign and at most the id of the trust domain") {
        val root = Authority.root(DOMAIN_ID)
        val leaf = root.leaf(WORKLOAD)
        X509SvidRules.path(emptyList()).failure() shouldBe X509SvidFailure.EmptyChain
        X509SvidRules.path(listOf(leaf.certificate, root.certificate)).value() shouldBe workload
        X509SvidRules.path(listOf(leaf.certificate, leaf.certificate)).failure() shouldBe
            X509SvidFailure.SigningCertificate
        val signingOnly = root.issue(name = Authority.INTERMEDIATE) {
            basicConstraints(isCa = true)
            keyUsage(setOf(KeyUsage.DigitalSignature, KeyUsage.CrlSign))
        }
        X509SvidRules.path(listOf(leaf.certificate, signingOnly.certificate)).failure() shouldBe
            X509SvidFailure.SigningCertificate
        val named = root.intermediate("https://example.org/ca", DOMAIN_ID)
        X509SvidRules.path(listOf(leaf.certificate, named.certificate)).value() shouldBe workload
        listOf("spiffe://example.com", "spiffe://example.org/ca", "spiffe://Example.org").forEach { uri ->
            X509SvidRules.path(listOf(leaf.certificate, root.intermediate(uri).certificate)).failure() shouldBe
                X509SvidFailure.SigningCertificate
        }
        X509SvidRules.path(listOf(root.leaf("spiffe://example.org/x").certificate)).value().path shouldBe "/x"
    }

    test("an SVID of the workload checks its chain, its key and its hint") {
        val root = Authority.root(DOMAIN_ID)
        val intermediate = root.intermediate(DOMAIN_ID)
        val leaf = intermediate.leaf(WORKLOAD)
        val chain = listOf(leaf.certificate, intermediate.certificate)
        val svid = X509Svid.of(chain = chain, privateKey = leaf.privateKey, hint = HINT).value()
        svid.id shouldBe workload
        svid.chain shouldBe chain
        svid.certificate shouldBe leaf.certificate
        svid.hint shouldBe HINT
        svid.privateKey shouldBe leaf.privateKey
        svid.toString() shouldContain HINT
        svid.toString() shouldNotContain leaf.privateKey.toString()
        val unhinted = X509Svid.of(chain = chain, privateKey = leaf.privateKey).value()
        unhinted.toString() shouldContain "none"
        X509Svid.of(chain = chain, privateKey = intermediate.privateKey).failure() shouldBe X509SvidFailure.KeyMismatch
        val rsa = crypto.keys.generate(KeyType.Rsa3072).privateKey
        X509Svid.of(chain = chain, privateKey = rsa).failure() shouldBe X509SvidFailure.KeyMismatch
        X509Svid.of(chain = emptyList(), privateKey = leaf.privateKey).failure() shouldBe X509SvidFailure.EmptyChain
        val short = SpiffeLimits(maximumChainLength = 1)
        X509Svid.of(chain = chain, privateKey = leaf.privateKey, limits = short).failure() shouldBe
            X509SvidFailure.LimitExceeded
        val longHint = "h".repeat(X509Svid.MAXIMUM_HINT_LENGTH + 1)
        X509Svid.of(chain = chain, privateKey = leaf.privateKey, hint = longHint).failure() shouldBe
            X509SvidFailure.LimitExceeded
        val longestHint = "h".repeat(X509Svid.MAXIMUM_HINT_LENGTH)
        X509Svid.of(chain = chain, privateKey = leaf.privateKey, hint = longestHint).value().hint shouldBe longestHint
        X509Svid.of(chain = listOf(intermediate.certificate), privateKey = intermediate.privateKey).failure() shouldBe
            X509SvidFailure.TrustDomainId
    }

    test("SVIDs of the workload compare by chain, key and hint") {
        val root = Authority.root(DOMAIN_ID)
        val leaf = root.leaf(WORKLOAD)
        val svid = X509Svid.of(chain = leaf.chain, privateKey = leaf.privateKey, hint = HINT).value()
        val same = X509Svid.of(chain = leaf.chain, privateKey = leaf.privateKey, hint = HINT).value()
        svid shouldBe same
        svid.hashCode() shouldBe same.hashCode()
        svid.equals(leaf) shouldBe false
        X509Svid.of(chain = leaf.chain, privateKey = leaf.privateKey).value() shouldNotBe svid
        val other = root.leaf(WORKLOAD)
        X509Svid.of(chain = other.chain, privateKey = other.privateKey, hint = HINT).value() shouldNotBe svid
        val copy = crypto.keys.decodePrivate(crypto.keys.encodePrivate(leaf.privateKey)).value()
        X509Svid.of(chain = leaf.chain, privateKey = copy, hint = HINT).value() shouldNotBe svid
        val pair = crypto.keys.generate(KeyType.P256)
        val rekeyed = root.issue(name = Authority.LEAF, extensions = Authority.leafOf(listOf(WORKLOAD)))
        X509Svid.of(chain = rekeyed.chain, privateKey = pair.privateKey).failure() shouldBe X509SvidFailure.KeyMismatch
    }
})
