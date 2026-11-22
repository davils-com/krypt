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

package com.davils.krypt.spiffe

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.lang.reflect.Modifier

class AuditJavaReachabilityTest : FunSpec({
    test("Java cannot construct a trust domain or a SPIFFE id that bypasses the parser") {
        val domainConstructor = TrustDomain::class.java.getDeclaredConstructor(String::class.java)
        val forgedDomain = runCatching { domainConstructor.newInstance("Evil Domain/..") }.getOrNull()
        val idConstructor = SpiffeId::class.java.getDeclaredConstructor(TrustDomain::class.java, String::class.java)
        val forgedId = runCatching { idConstructor.newInstance(TrustDomain.of("example.org"), "/../admin?x#y") }
            .getOrNull()
        println(
            "AUDIT java: TrustDomain public=${Modifier.isPublic(domainConstructor.modifiers)} forged=$forgedDomain, " +
                "SpiffeId public=${Modifier.isPublic(idConstructor.modifiers)} forged=$forgedId",
        )
        Modifier.isPublic(domainConstructor.modifiers) shouldBe false
        Modifier.isPublic(idConstructor.modifiers) shouldBe false
    }
})
