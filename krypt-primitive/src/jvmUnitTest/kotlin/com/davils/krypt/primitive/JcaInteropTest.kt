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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.primitive

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.RandomSource
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val FILL: Byte = 7
private const val SIZE: Int = 4

class JcaInteropTest : FunSpec({
    test("the JCA key signs like the krypt key it comes from") {
        val crypto = Crypto()
        val pair = crypto.keys.generate(KeyType.P256)
        val key = crypto.jcaPrivateKey(pair.privateKey)
        key.algorithm shouldBe "EC"
        crypto.jcaPrivateKey(pair.privateKey) shouldBe key
        pair.privateKey.destroy()
        shouldThrow<IllegalStateException> { crypto.jcaPrivateKey(pair.privateKey) }
    }

    test("the randomness of the platform is a plain SecureRandom and any other source is adapted") {
        val platform = Crypto().secureRandom()
        platform.algorithm.isNotEmpty() shouldBe true
        val fixed = RandomSource { target -> target.fill(FILL) }
        val adapted = Crypto(environment { random = fixed }).secureRandom()
        val bytes = ByteArray(SIZE)
        adapted.nextBytes(bytes)
        bytes.toList() shouldBe List(SIZE) { FILL }
    }
})
