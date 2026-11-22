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

package com.davils.krypt.tls.trust

import com.davils.krypt.tls.fixture.trustingClient
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import java.security.Security

private val DISTRUSTED_ROOTS: List<String> = listOf(
    "HiPKI Root CA - G1",
    "Entrust Root Certification Authority",
    "Entrust.net Certification Authority (2048)",
    "AffirmTrust",
    "Chambers of Commerce Root - 2008",
    "Global Chambersign Root - 2008",
    "Camerfirma",
)

class AuditSystemAnchorsTest : FunSpec({
    test("system anchors the JDK distrusts for TLS are not trusted without the distrust date") {
        val policies = Security.getProperty("jdk.security.caDistrustPolicies").orEmpty()
        val client = trustingClient { isSystemIncluded = true }
        val names = client.trustManager.anchors.map { anchor -> anchor.name.toString() }
        val distrusted = names.filter { name -> DISTRUSTED_ROOTS.any { root -> name.contains(root) } }
        println("AUDIT system anchors: policies=$policies, anchors=${names.size}, distrusted=$distrusted")
        distrusted.shouldBeEmpty()
    }
})
