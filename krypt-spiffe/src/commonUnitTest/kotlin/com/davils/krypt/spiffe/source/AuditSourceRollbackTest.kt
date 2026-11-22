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

import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.failure
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private fun setOf(sequence: Long?): BundleSet = BundleSet(listOf(TrustBundle(domain, sequence = sequence)))

class AuditSourceRollbackTest : FunSpec({
    test("a bundle without a sequence does not reset the sequence an older bundle is checked against") {
        val source = X509Source()
        source.updateBundles(setOf(5L)).failure() shouldBe null
        source.updateBundles(setOf(1L)).failure() shouldBe SourceFailure.Rollback
        source.updateBundles(setOf(null)).failure() shouldBe null
        source.updateBundles(setOf(1L)).failure() shouldBe SourceFailure.Rollback
    }

    test("dropping a trust domain for one update does not reset the sequence an older bundle is checked against") {
        val source = X509Source()
        source.updateBundles(setOf(5L)).failure() shouldBe null
        source.updateBundles(BundleSet.Empty).failure() shouldBe null
        source.updateBundles(setOf(1L)).failure() shouldBe SourceFailure.Rollback
    }
})
