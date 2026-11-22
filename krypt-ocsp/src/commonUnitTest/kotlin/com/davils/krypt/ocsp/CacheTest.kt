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

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.ocsp.fixture.NOW
import com.davils.krypt.ocsp.fixture.SHA256_BYTES
import com.davils.krypt.ocsp.fixture.filled
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

private const val THIRD: Long = 3L

private fun idOf(serial: Long): CertId = CertId(
    hashAlgorithm = DigestAlgorithm.Sha256,
    issuerNameHash = filled(SHA256_BYTES),
    issuerKeyHash = filled(SHA256_BYTES),
    serialNumber = DerInteger.of(serial),
)

class CacheTest : FunSpec({
    test("the cache keeps fresh responses and makes room by expiry") {
        val cache = OcspResponseCache(capacity = 2)
        val first = ByteString(1)
        val second = ByteString(2)
        val third = ByteString(3)
        cache.put(idOf(1L), first, NOW + 1.hours)
        cache.put(idOf(2L), second, NOW + 2.hours)
        cache.get(idOf(1L), NOW) shouldBe first
        cache.put(idOf(1L), third, NOW + 3.hours)
        cache.size() shouldBe 2
        cache.get(idOf(1L), NOW) shouldBe third
        cache.put(idOf(THIRD), first, NOW + 1.days)
        cache.get(idOf(2L), NOW) shouldBe null
        cache.get(idOf(1L), NOW + 3.hours) shouldBe null
        cache.size() shouldBe 1
        cache.get(idOf(THIRD), NOW) shouldBe first
        cache.clear()
        cache.size() shouldBe 0
        cache.toString() shouldContain "capacity=2"
    }

    test("capacities have bounds") {
        shouldThrow<IllegalArgumentException> { OcspResponseCache(capacity = 0) }
        shouldThrow<IllegalArgumentException> {
            OcspResponseCache(capacity = OcspResponseCache.HARD_MAXIMUM_CAPACITY + 1)
        }
        OcspResponseCache().capacity shouldBe OcspResponseCache.DEFAULT_CAPACITY
    }
})
