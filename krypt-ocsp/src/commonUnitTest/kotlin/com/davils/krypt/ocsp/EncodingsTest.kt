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

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.ocsp.fixture.Scenario
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val RESPONDER: String = "http://ocsp.example.com"
private const val ESCAPED: String = "%2B%2F8%3D"
private const val LONG_HOST: Int = 300
private const val PLUS_SLASH: Byte = -5
private const val ALL_ONES: Byte = -1
private val SPECIAL: ByteString = ByteString(byteArrayOf(PLUS_SLASH, ALL_ONES))

class EncodingsTest : FunSpec({
    test("GET requests escape their Base64") {
        val special = OcspRequest(certIds = emptyList(), nonce = null, encoded = SPECIAL)
        OcspEncodings.pathSegment(special) shouldBe ESCAPED
        OcspEncodings.getUrl(RESPONDER, special) shouldBe "$RESPONDER/$ESCAPED"
        OcspEncodings.getUrl("$RESPONDER/", special) shouldBe "$RESPONDER/$ESCAPED"
        OcspEncodings.isGetSuitable(RESPONDER, special) shouldBe true
        OcspEncodings.isGetSuitable("http://" + "a".repeat(LONG_HOST), special) shouldBe false
        listOf(ESCAPED, ESCAPED.lowercase(), "+/8=", "%2B/8%3d").forEach { segment ->
            OcspEncodings.requestOf(segment).getOrNull() shouldBe SPECIAL
        }
        OcspEncodings.REQUEST_MEDIA_TYPE shouldBe "application/ocsp-request"
        OcspEncodings.RESPONSE_MEDIA_TYPE shouldBe "application/ocsp-response"
    }

    test("a real request survives the path") {
        val request = Scenario.create().request()
        val segment = OcspEncodings.pathSegment(request)
        OcspEncodings.requestOf(segment).getOrNull() shouldBe request.encoded
    }

    test("segments with other escapes or bad Base64 are refused") {
        listOf("%2C8%3D", "%2", "+/8", "!!!!", "%%%%").forEach { segment ->
            OcspEncodings.requestOf(segment).failureOrNull() shouldBe OcspFailure.Malformed
        }
    }
})
