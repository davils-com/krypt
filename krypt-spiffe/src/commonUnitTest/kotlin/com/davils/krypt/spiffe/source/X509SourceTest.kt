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

package com.davils.krypt.spiffe.source

import com.davils.krypt.spiffe.SpiffeLimits
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.fixture.Authority
import com.davils.krypt.spiffe.fixture.DOMAIN_ID
import com.davils.krypt.spiffe.fixture.FOREIGN_WORKLOAD
import com.davils.krypt.spiffe.fixture.WORKLOAD
import com.davils.krypt.spiffe.fixture.crypto
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.failure
import com.davils.krypt.spiffe.fixture.foreign
import com.davils.krypt.spiffe.fixture.value
import com.davils.krypt.spiffe.x509.X509Svid
import com.davils.krypt.spiffe.x509.X509SvidValidator
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private const val INTERNAL: String = "internal"
private const val EXTERNAL: String = "external"

private suspend fun svidOf(root: Authority, id: String = WORKLOAD, hint: String? = null): X509Svid {
    val leaf = root.leaf(id)
    return X509Svid.of(chain = leaf.chain, privateKey = leaf.privateKey, hint = hint).value()
}

class X509SourceTest : FunSpec({
    test("a source starts empty and serves what the application pushes") {
        val source = X509Source()
        source.svid().shouldBeNull()
        source.svids shouldBe emptyList()
        source.bundle(domain).shouldBeNull()
        val root = Authority.root(DOMAIN_ID)
        val internal = svidOf(root, hint = INTERNAL)
        val external = svidOf(root, hint = EXTERNAL)
        val twin = svidOf(root, hint = INTERNAL)
        val bundles = BundleSet(listOf(TrustBundle(domain, listOf(root.certificate), sequence = 1L)))
        source.update(listOf(internal, external, twin), bundles).value() shouldBe Unit
        source.svid() shouldBe internal
        source.svid(EXTERNAL) shouldBe external
        source.svid(INTERNAL) shouldBe internal
        source.svid("other").shouldBeNull()
        source.bundle(domain) shouldBe bundles[domain]
        source.bundles shouldBe bundles
        source.toString() shouldContain "svids=3"
        source.limits shouldBe SpiffeLimits.Default
        val validator = X509SvidValidator(crypto, source)
        validator.validate(internal.chain).value().id shouldBe internal.id
    }

    test("an update is complete and atomic, and a refused one keeps the current material") {
        val root = Authority.root(DOMAIN_ID)
        val svid = svidOf(root)
        val first = TrustBundle(domain, listOf(root.certificate), sequence = 2L)
        val source = X509Source()
        source.update(listOf(svid), BundleSet(listOf(first))).value()
        source.update(emptyList(), BundleSet(listOf(first))).failure() shouldBe SourceFailure.NoSvid
        source.update(listOf(svid), BundleSet()).failure() shouldBe SourceFailure.MissingBundle
        val older = TrustBundle(domain, listOf(root.certificate), sequence = 1L)
        source.update(listOf(svid), BundleSet(listOf(older))).failure() shouldBe SourceFailure.Rollback
        source.updateBundles(BundleSet(listOf(older))).failure() shouldBe SourceFailure.Rollback
        source.updateBundles(BundleSet()).failure() shouldBe SourceFailure.MissingBundle
        source.bundles[domain] shouldBe first
        source.svids shouldBe listOf(svid)
        val unsequenced = TrustBundle(domain, listOf(root.certificate))
        source.update(listOf(svid), BundleSet(listOf(unsequenced))).value()
        source.updateBundles(BundleSet(listOf(older))).value()
        val same = TrustBundle(domain, listOf(root.certificate), sequence = 1L)
        source.updateBundles(BundleSet(listOf(same, TrustBundle(foreign)))).value()
        source.bundles.trustDomains shouldBe listOf(foreign, domain)
        source.updateBundles(BundleSet(listOf(same))).value()
        source.bundles.trustDomains shouldBe listOf(domain)
    }

    test("a source that only validates takes bundles without SVIDs, within its limits") {
        val root = Authority.root(DOMAIN_ID)
        val foreignRoot = Authority.root()
        val source = X509Source(SpiffeLimits(maximumSvids = 1, maximumTrustDomains = 1))
        source.updateBundles(BundleSet(listOf(TrustBundle(domain, listOf(root.certificate))))).value()
        source.svid().shouldBeNull()
        val two = BundleSet(listOf(TrustBundle(domain), TrustBundle(foreign, listOf(foreignRoot.certificate))))
        source.updateBundles(two).failure() shouldBe SourceFailure.LimitExceeded
        val svids = listOf(svidOf(root), svidOf(root))
        source.update(svids, BundleSet(listOf(TrustBundle(domain)))).failure() shouldBe SourceFailure.LimitExceeded
        val foreignSvid = svidOf(foreignRoot, id = FOREIGN_WORKLOAD)
        source.update(listOf(foreignSvid), BundleSet(listOf(TrustBundle(domain)))).failure() shouldBe
            SourceFailure.MissingBundle
    }
})
