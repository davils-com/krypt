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

package com.davils.krypt.ocsp

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.ocsp.fixture.NOW
import com.davils.krypt.ocsp.fixture.Scenario
import com.davils.krypt.ocsp.fixture.ocsp
import com.davils.krypt.x509.path.RevocationStatus
import com.davils.krypt.x509.path.TrustAnchor
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class ForeignCodeTest : FunSpec({
    test("a failing source of responses leaves the status unknown") {
        val scenario = Scenario.create()
        val checker = OcspRevocationChecker(ocsp, { _, _, _ -> error("responder down") })
        val anchor = TrustAnchor.of(scenario.authority.certificate)
        val status = checker.check(certificate = scenario.leaf, issuer = null, anchor = anchor, at = NOW)
        status shouldBe RevocationStatus.Unknown
    }

    test("a failing status source is answered with an internal error that is not cached") {
        val scenario = Scenario.create()
        val cache = OcspResponseCache()
        val responder = scenario.authority.responder(source = { _ -> error("database down") }, cache = cache)
        val answer = ocsp.decodeResponse(responder.respond(scenario.request())).getOrNull()
        answer?.status shouldBe OcspResponseStatus.InternalError
        val presigned = ocsp.decodeResponse(responder.presign(scenario.leaf.serialNumber)).getOrNull()
        presigned?.status shouldBe OcspResponseStatus.InternalError
        cache.size() shouldBe 0
    }

    test("the size of the nonce is checked when the checker is built") {
        val source = OcspResponseSource { _, _, _ -> null }
        shouldThrow<IllegalArgumentException> {
            OcspRevocationChecker(ocsp = ocsp, source = source, nonceBytes = Ocsp.MINIMUM_NONCE_SIZE - 1)
        }
        shouldThrow<IllegalArgumentException> {
            OcspRevocationChecker(ocsp = ocsp, source = source, nonceBytes = Ocsp.MAXIMUM_NONCE_SIZE + 1)
        }
        OcspRevocationChecker(ocsp = ocsp, source = source, nonceBytes = Ocsp.MAXIMUM_NONCE_SIZE).toString()
    }
})
