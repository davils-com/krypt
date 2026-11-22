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
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import java.lang.reflect.Modifier
import java.security.KeyPairGenerator
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val MODULUS_BYTES: Int = 512
private const val EXPONENT_BYTES: Int = 11
private const val WEAK_RSA_BITS: Int = 1_024
private const val DISGUISED_RSA_BITS: Int = 4_096

private fun hostileRsaSpki(): ByteString {
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

class AuditJcaTest : FunSpec({
    test("A-2: verifying with an RSA key that decodePublic accepted but JCA rejects is Invalid, not an exception") {
        val crypto = Crypto()
        val key = crypto.keys.decodePublic(hostileRsaSpki()).getOrNull()
        key shouldNotBe null
        val verification = shouldNotThrowAny {
            crypto.signatures.verify(
                key = checkNotNull(key),
                data = "message".encodeToByteString(),
                signature = ByteString(ByteArray(MODULUS_BYTES)),
                algorithm = SignatureAlgorithm.RsaPssSha256,
            )
        }
        verification shouldBe Verification.Invalid
    }

    test("A-5: the constructors of the key types are not reachable from Java, so the policy cannot be bypassed") {
        val crypto = Crypto()
        val weak = KeyPairGenerator.getInstance("RSA").apply { initialize(WEAK_RSA_BITS) }.generateKeyPair()
        val constructor = PublicKey::class.java.declaredConstructors.single()
        val secretConstructor = SecretKey::class.java.declaredConstructors.single { candidate ->
            candidate.parameterCount == 1
        }
        val privateConstructor = PrivateKey::class.java.declaredConstructors.single()
        val reachable = listOf(constructor, secretConstructor, privateConstructor).filter { candidate ->
            Modifier.isPublic(candidate.modifiers)
        }
        val disguised = constructor.newInstance(
            KeyFamily.Rsa,
            null,
            DISGUISED_RSA_BITS,
            ByteString(weak.public.encoded),
            ByteString(),
        ) as PublicKey
        val encrypted = runCatching {
            crypto.encryptions.encrypt(publicKey = disguised, plaintext = "message".encodeToByteString())
        }
        encrypted.isSuccess shouldBe false
        reachable shouldBe emptyList()
    }

    test("A-11: a policy that demands a FIPS provider refuses to run without one") {
        val fips = Crypto(environment { policy = CryptoPolicy.Fips })
        CryptoPolicy.Fips.isFipsProviderRequired shouldBe true
        shouldThrow<CryptoException> { fips.digests.digest("message".encodeToByteString()) }
    }
})
