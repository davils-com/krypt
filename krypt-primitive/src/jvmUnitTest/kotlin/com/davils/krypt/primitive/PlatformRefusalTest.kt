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

package com.davils.krypt.primitive

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val MODULUS_BYTES: Int = 512
private const val EXPONENT_BYTES: Int = 11
private const val REFUSAL: String = "The platform refused the key or the input"

private fun largeExponentSpki(): ByteString {
    val modulus = ByteArray(MODULUS_BYTES) { 0x5A }.also { bytes ->
        bytes[0] = 0xC0.toByte()
        bytes[MODULUS_BYTES - 1] = 0x01
    }
    val exponent = ByteArray(EXPONENT_BYTES).also { bytes ->
        bytes[0] = 0x01
        bytes[EXPONENT_BYTES - 1] = 0x01
    }
    val publicKey = Der.encode {
        sequence {
            integer(DerInteger.ofMagnitude(ByteString(modulus)))
            integer(DerInteger.ofMagnitude(ByteString(exponent)))
        }
    }
    return Der.encode {
        sequence {
            sequence {
                objectIdentifier(ObjectIdentifier.of("1.2.840.113549.1.1.1"))
                nullValue()
            }
            bitString(BitString(publicKey))
        }
    }
}

class PlatformRefusalTest : FunSpec({
    val crypto = Crypto()

    test("an RSA key JCA refuses although krypt read it encrypts nothing and hides the failure of JCA") {
        val key = checkNotNull(crypto.keys.decodePublic(largeExponentSpki()).getOrNull())
        val refused = shouldThrow<CryptoException> {
            crypto.encryptions.encrypt(publicKey = key, plaintext = "message".encodeToByteString())
        }
        refused.message shouldBe REFUSAL
        refused.cause.shouldBeNull()
    }

    test("an ML-KEM encapsulation of the wrong size opens nothing") {
        val pair = crypto.keys.generate(KeyType.MlKem768)
        val opened = crypto.kems.decapsulate(
            recipient = pair.privateKey,
            encapsulated = ByteString(ByteArray(EXPONENT_BYTES)),
            algorithm = KemAlgorithm.MlKem768,
        )
        opened.shouldBeNull()
    }
})
