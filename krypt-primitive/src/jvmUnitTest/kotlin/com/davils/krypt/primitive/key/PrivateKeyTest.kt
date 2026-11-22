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

package com.davils.krypt.primitive.key

import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.UnsupportedAlgorithmException
import com.davils.krypt.primitive.fixture.on
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.encodeToByteString

private const val BITS: Int = 256

class PrivateKeyTest : FunSpec({
    test("a key with neither encoding nor handle refuses to sign") {
        val crypto = Crypto()
        val empty = PrivateKey(
            family = KeyFamily.Ed25519,
            curve = null,
            bits = BITS,
            publicKey = null,
            pkcs8 = null,
            platformHandle = null,
        )
        shouldThrow<IllegalStateException> { crypto.signatures.sign(key = empty, data = "x".encodeToByteString()) }
        empty.withPublic(crypto.keys.generate(KeyType.Ed25519).publicKey).isExtractable shouldBe false
    }

    test("a provider without a generator refuses to generate") {
        shouldThrow<UnsupportedAlgorithmException> { on("SUN").keys.generate(KeyType.X25519) }
    }
})
