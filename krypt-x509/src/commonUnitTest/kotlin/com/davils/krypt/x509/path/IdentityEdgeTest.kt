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

import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val LABEL: Int = 63
private const val NAME: Int = 254

class IdentityEdgeTest : FunSpec({
    test("references that are no DNS names never match") {
        val root = Authority.root()
        val label = "a".repeat(LABEL)
        val issued = root.issue(
            "x",
            extensions = { subjectAlternativeNames(listOf(GeneralName.Dns("$label.example.com"))) },
        )
        val certificate = issued.certificate
        ServiceIdentity.matches(certificate, "$label.example.com") shouldBe true
        ServiceIdentity.matches(certificate, "a".repeat(NAME)) shouldBe false
        ServiceIdentity.matches(certificate, "a-.example.com") shouldBe false
        ServiceIdentity.matches(certificate, ".example.com") shouldBe false
        ServiceIdentity.matches(certificate, "abä.example.com") shouldBe false
        ServiceIdentity.matches(certificate, "AB.example.com") shouldBe false
    }

    test("IP addresses in odd forms are refused") {
        listOf(
            "1.2.3.04",
            "1.2.3.256",
            "1.2.3.-1",
            "1:2:3:4::5:6:7:8",
            "1::fffff",
            "1::g",
            "1:2::3:4:5:6:7:8",
        ).forEach { text ->
            GeneralName.IpAddress.parseOrNull(text) shouldBe null
        }
    }
})
