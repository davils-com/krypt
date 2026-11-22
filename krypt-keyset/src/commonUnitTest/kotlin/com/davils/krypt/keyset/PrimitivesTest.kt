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

package com.davils.krypt.keyset

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.keyset.fixture.flipped
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.keyset.fixture.utf8
import com.davils.krypt.primitive.Verification
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val MESSAGE: String = "the ledger of 2026"
private const val CONTEXT: String = "record 42"
private const val LAST_PREFIX_BYTE: Int = 8
private const val DERIVED_BYTES: Int = 32
private const val SHORT_BYTES: Int = 16

class PrimitivesTest : FunSpec({
    test("a key set encrypts with its primary key and decrypts with the key the ciphertext names") {
        val first = keysets.generate(KeyPurpose.Aead())
        val old = keysets.aead(first).encrypt(plaintext = utf8(MESSAGE), associatedData = utf8(CONTEXT))
        val rotated = keysets.rotate(first)
        val aead = keysets.aead(rotated)
        aead.decrypt(ciphertext = old, associatedData = utf8(CONTEXT)) shouldBe utf8(MESSAGE)
        val fresh = aead.encrypt(utf8(MESSAGE))
        fresh.substring(startIndex = 1, endIndex = LAST_PREFIX_BYTE + 1) shouldBe rotated.primaryId.bytes
        aead.decrypt(fresh) shouldBe utf8(MESSAGE)
        aead.decrypt(old) shouldBe null
        aead.decrypt(flipped(old, LAST_PREFIX_BYTE)) shouldBe null
        aead.decrypt(ciphertext = flipped(old, old.size - 1), associatedData = utf8(CONTEXT)) shouldBe null
        aead.decrypt(ciphertext = flipped(old, 0), associatedData = utf8(CONTEXT)) shouldBe null
        aead.decrypt(ByteString()) shouldBe null
        aead.decrypt(
            ciphertext = old.substring(startIndex = 0, endIndex = LAST_PREFIX_BYTE + 2),
            associatedData = utf8(CONTEXT),
        ) shouldBe null
        val disabled = keysets.disable(rotated, first.primaryId)
        keysets.aead(disabled).decrypt(ciphertext = old, associatedData = utf8(CONTEXT)) shouldBe null
        aead.algorithm shouldBe rotated.purpose.let { purpose -> (purpose as KeyPurpose.Aead).algorithm }
        aead.toString() shouldContain "KeysetAead"
        aead.keyset shouldBe rotated
        shouldThrow<IllegalArgumentException> { keysets.aead(keysets.generate(KeyPurpose.Mac())) }
    }

    test("a key set computes tags with its primary key and verifies them with every enabled key") {
        val first = keysets.generate(KeyPurpose.Mac())
        val tag = keysets.mac(first).compute(utf8(MESSAGE))
        val rotated = keysets.rotate(first)
        val mac = keysets.mac(rotated)
        mac.verify(data = utf8(MESSAGE), tag = tag) shouldBe Verification.Valid
        mac.verify(data = utf8(CONTEXT), tag = tag) shouldBe Verification.Invalid
        mac.verify(data = utf8(MESSAGE), tag = ByteString()) shouldBe Verification.Invalid
        mac.computeAll(utf8(MESSAGE)) shouldBe listOf(mac.compute(utf8(MESSAGE)), tag)
        mac.algorithm shouldBe (rotated.purpose as KeyPurpose.Mac).algorithm
        mac.toString() shouldContain "KeysetMac"
        mac.keyset shouldBe rotated
        shouldThrow<IllegalArgumentException> { keysets.mac(keysets.generate(KeyPurpose.Aead())) }
    }

    test("a key set signs with its primary key and its public part verifies") {
        val keyset = keysets.generate(KeyPurpose.Signing(KeyType.P256))
        val signer = keysets.signer(keyset)
        val signature = signer.sign(utf8(MESSAGE))
        val verifier = keysets.verifier(keysets.publicKeyset(keyset))
        verifier.verify(data = utf8(MESSAGE), signature = signature) shouldBe Verification.Valid
        verifier.verify(data = utf8(CONTEXT), signature = signature) shouldBe Verification.Invalid
        verifier.verify(data = utf8(MESSAGE), signature = flipped(signature, 1)) shouldBe Verification.Invalid
        signer.keyset shouldBe keyset
        signer.toString() shouldContain "KeysetSigner"
        verifier.toString() shouldContain "KeysetVerifier"
        verifier.keyset.isPublic shouldBe true
        shouldThrow<IllegalArgumentException> { keysets.signer(keysets.publicKeyset(keyset)) }
        shouldThrow<IllegalArgumentException> { keysets.signer(keysets.generate(KeyPurpose.Mac())) }
        shouldThrow<IllegalArgumentException> { keysets.verifier(keysets.generate(KeyPurpose.Mac())) }
    }

    test("a public key set encrypts and only the private key set decrypts") {
        val keyset = keysets.generate(KeyPurpose.Hybrid())
        val encrypter = keysets.encrypter(keysets.publicKeyset(keyset))
        val decrypter = keysets.decrypter(keyset)
        val sealed = encrypter.encrypt(utf8(MESSAGE), associatedData = utf8(CONTEXT), info = utf8(CONTEXT))
        decrypter.decrypt(sealed, associatedData = utf8(CONTEXT), info = utf8(CONTEXT)) shouldBe utf8(MESSAGE)
        decrypter.decrypt(sealed, info = utf8(CONTEXT)) shouldBe null
        decrypter.decrypt(ByteString()) shouldBe null
        val plain = encrypter.encrypt(utf8(MESSAGE))
        decrypter.decrypt(plain) shouldBe utf8(MESSAGE)
        encrypter.suite shouldBe decrypter.suite
        encrypter.keyset.isPublic shouldBe true
        decrypter.keyset shouldBe keyset
        encrypter.toString() shouldContain "HybridEncrypter"
        decrypter.toString() shouldContain "HybridDecrypter"
        shouldThrow<IllegalArgumentException> { keysets.decrypter(keysets.publicKeyset(keyset)) }
        shouldThrow<IllegalArgumentException> { keysets.encrypter(keysets.generate(KeyPurpose.Mac())) }
        shouldThrow<IllegalArgumentException> { keysets.decrypter(keysets.generate(KeyPurpose.Mac())) }
    }

    test("keys derived for different contexts are independent and repeatable") {
        val keyset = keysets.rotate(keysets.generate(KeyPurpose.Mac()))
        val first = keysets.derive(keyset = keyset, context = utf8(MESSAGE))
        first.bits shouldBe DERIVED_BYTES * Byte.SIZE_BITS
        keysets.derive(keyset = keyset, context = utf8(MESSAGE)) shouldBe first
        keysets.derive(keyset = keyset, context = utf8(CONTEXT)) shouldNotBe first
        val old = keysets.derive(
            keyset = keyset,
            context = utf8(MESSAGE),
            size = SHORT_BYTES,
            id = keyset.keys.first().id,
        )
        old.bits shouldBe SHORT_BYTES * Byte.SIZE_BITS
        shouldThrow<IllegalArgumentException> { keysets.derive(keyset = keyset, context = utf8(MESSAGE), size = 1) }
        shouldThrow<IllegalArgumentException> {
            keysets.derive(
                keyset = keyset,
                context = utf8(MESSAGE),
                size = DERIVED_BYTES * 4,
            )
        }
        val signing = keysets.generate(KeyPurpose.Signing())
        shouldThrow<IllegalArgumentException> { keysets.derive(keyset = signing, context = utf8(MESSAGE)) }
        val disabled = keysets.disable(keyset, keyset.keys.first().id)
        shouldThrow<IllegalArgumentException> {
            keysets.derive(
                keyset = disabled,
                context = utf8(MESSAGE),
                id = keyset.keys.first().id,
            )
        }
    }
})
