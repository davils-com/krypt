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

package com.davils.krypt.authority

import com.davils.krypt.authority.fixture.issued
import com.davils.krypt.authority.fixture.rootAuthority
import com.davils.krypt.authority.fixture.serverRequest
import com.davils.krypt.authority.fixture.testEnvironment
import com.davils.krypt.core.audit.AuditEntry
import com.davils.krypt.core.audit.AuditRefusedException
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class AuditTest : FunSpec({
    test("issuance, revocation and lists are audited") {
        val entries = mutableListOf<AuditEntry>()
        val crypto = Crypto(testEnvironment { audit({ entry -> entries += entry }, required = true) })
        val root = rootAuthority(on = crypto).authority
        val leaf = root.issued(serverRequest())
        root.revoke(leaf.serialNumber)
        root.revocationList()
        entries.map { entry -> entry.action.value } shouldBe
            listOf("authority.issue", "authority.revoke", "authority.publish-crl")
        entries.first().attributes["profile"] shouldBe "tls-server"
    }

    test("a required audit that fails stops the authority") {
        val crypto = Crypto(testEnvironment { audit({ _ -> error("the audit is down") }, required = true) })
        val root = rootAuthority(on = crypto).authority
        shouldThrow<AuditRefusedException> { root.issue(serverRequest()) }
    }
})
