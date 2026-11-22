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

package com.davils.krypt.spiffe.bundle

import com.davils.krypt.spiffe.fixture.Authority
import com.davils.krypt.spiffe.fixture.DOMAIN_ID
import com.davils.krypt.spiffe.fixture.X509_USE
import com.davils.krypt.spiffe.fixture.bundleOf
import com.davils.krypt.spiffe.fixture.chainOf
import com.davils.krypt.spiffe.fixture.codec
import com.davils.krypt.spiffe.fixture.domain
import com.davils.krypt.spiffe.fixture.entry
import com.davils.krypt.spiffe.fixture.failure
import com.davils.krypt.spiffe.fixture.jwkOf
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

class X509AuthorityChainTest : FunSpec({
    test("an X.509 authority whose x5c holds more than one certificate is refused") {
        val root = Authority.root(DOMAIN_ID)
        val other = Authority.root(DOMAIN_ID)
        val publicKey = root.certificate.publicKey.shouldNotBeNull()
        val text = bundleOf(entry(jwkOf(publicKey), X509_USE, chainOf(root.certificate, other.certificate)))
        codec.decode(domain, text).failure() shouldBe BundleFailure.InvalidKey
    }

    test("an X.509 authority whose x5c holds exactly one certificate is read") {
        val root = Authority.root(DOMAIN_ID)
        val publicKey = root.certificate.publicKey.shouldNotBeNull()
        val text = bundleOf(entry(jwkOf(publicKey), X509_USE, chainOf(root.certificate)))
        codec.decode(domain, text).failure() shouldBe null
    }
})
