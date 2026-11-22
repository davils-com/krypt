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

package com.davils.krypt.primitive.key

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.UnsupportedAlgorithmException
import com.davils.krypt.primitive.fixture.on
import com.davils.krypt.primitive.jcaPrivateKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.encodeToByteString

class PrivateKeyTest : FunSpec({
    test("a key of the platform whose handle is no JCA key refuses to sign and to be opened") {
        val crypto = Crypto()
        val publicKey = crypto.keys.generate(KeyType.Ed25519).publicKey
        val foreign = PrivateKey.ofPlatform(publicKey = publicKey, platformHandle = Any())
        foreign.isExtractable shouldBe false
        shouldThrow<CryptoException> { crypto.signatures.sign(key = foreign, data = "x".encodeToByteString()) }
        shouldThrow<IllegalStateException> { crypto.jcaPrivateKey(foreign) }
        foreign.withPublic(publicKey).isExtractable shouldBe false
        foreign.destroy()
        shouldThrow<IllegalStateException> { crypto.signatures.sign(key = foreign, data = "x".encodeToByteString()) }
    }

    test("a provider without a generator refuses to generate") {
        shouldThrow<UnsupportedAlgorithmException> { on("SUN").keys.generate(KeyType.X25519) }
    }
})
