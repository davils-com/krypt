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

package com.davils.krypt.tls.internal

import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.x509.Certificates
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

private const val LONG_LABEL: Int = 64
private const val LONG_NAME: Int = 128

class InternalsTest : FunSpec({
    test("host names are DNS names of letters, digits and hyphens or addresses") {
        HostNames.isDnsName("Server.Example.") shouldBe true
        HostNames.isDnsName("") shouldBe false
        HostNames.isDnsName("a".repeat(LONG_LABEL) + ".example") shouldBe false
        HostNames.isDnsName(List(LONG_NAME) { "ab" }.joinToString(".")) shouldBe false
        HostNames.isDnsName("under_score.example") shouldBe false
        HostNames.isDnsName("tilde~.example") shouldBe false
        HostNames.isDnsName("-lead.example") shouldBe false
        HostNames.isDnsName("trail-.example") shouldBe false
        HostNames.isDnsName("a..example") shouldBe false
        HostNames.isDnsName("10.0.0.1") shouldBe false
        HostNames.isHost("[::1]") shouldBe true
        HostNames.isHost("10.0.0.1") shouldBe true
        HostNames.isHost("bad host") shouldBe false
    }

    test("every key family has the key types JSSE asks for") {
        KeyFamily.entries.forEach { family -> KeyTypes.of(family) }
        KeyTypes.of(KeyFamily.Ed25519) shouldBe setOf("EdDSA", "Ed25519")
        KeyTypes.of(KeyFamily.Ed448) shouldBe setOf("EdDSA", "Ed448")
        KeyTypes.of(KeyFamily.Rsa) shouldBe setOf("RSA")
        KeyTypes.of(KeyFamily.MlDsa) shouldBe setOf("ML-DSA")
        KeyTypes.of(KeyFamily.MlKem).shouldBeEmpty()
    }

    test("a chain of the JDK is read only within bounds") {
        val pki = Pki.create()
        val certificate = JcaCertificates.toJca(pki.identity(CertificateProfile.TlsServer, SERVER_NAME).certificate)
        val codec = Certificates(crypto)
        JcaCertificates.fromJca(codec, arrayOf(certificate)).shouldNotBeNull()
        JcaCertificates.fromJca(codec, Array(JcaCertificates.MAXIMUM_CHAIN + 1) { certificate }).shouldBeNull()
        SystemTrust.load(codec, isIncluded = true).anchors.shouldNotBeEmpty()
        SystemTrust.load(codec, isIncluded = false).anchors.shouldBeEmpty()
    }
})
