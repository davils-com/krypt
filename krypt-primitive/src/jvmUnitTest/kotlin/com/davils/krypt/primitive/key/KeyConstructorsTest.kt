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

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.internal.KeyCodec
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import java.lang.reflect.Modifier
import java.security.KeyPairGenerator

private const val WEAK_RSA_BITS: Int = 1_024
private const val SHORT_KEY: Int = 8

class KeyConstructorsTest : FunSpec({
    test("the key types have no constructor Java can call, only private ones") {
        val types = listOf(PublicKey::class.java, PrivateKey::class.java, SecretKey::class.java)
        val constructors = types.flatMap { type -> type.declaredConstructors.toList() }
        val callable = constructors.filter { constructor ->
            !constructor.isSynthetic && !Modifier.isPrivate(constructor.modifiers)
        }
        callable shouldBe emptyList()
    }

    test("the policy sees the size of the encoding a key was made of") {
        val crypto = Crypto()
        val generator = KeyPairGenerator.getInstance("RSA").apply { initialize(WEAK_RSA_BITS) }
        val weak = generator.generateKeyPair()
        val key = checkNotNull(KeyCodec.publicKeyOf(ByteString(weak.public.encoded)).getOrNull())
        key.bits shouldBe WEAK_RSA_BITS
        crypto.keys.decodePublic(ByteString(weak.public.encoded)) shouldBe Outcome.Failure(KeyFailure.Refused)
        shouldThrow<PolicyViolationException> {
            crypto.encryptions.encrypt(publicKey = key, plaintext = "message".encodeToByteString())
        }
    }

    test("a symmetric key is never shorter than the minimum, however it is made") {
        shouldThrow<IllegalArgumentException> { SecretKey.adopt(SecretBytes.copyOf(ByteArray(SHORT_KEY))) }
        shouldThrow<IllegalArgumentException> { SecretKey.of(SecretBytes.copyOf(ByteArray(SHORT_KEY))) }
    }
})
