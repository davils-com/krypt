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

package com.davils.krypt.primitive.signature

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.fixture.RfcKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.fixture.hexOf
import com.davils.krypt.primitive.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val MESSAGE: String = "sign me"
private const val ML_DSA_44: Int = 44
private const val ML_DSA_87: Int = 87

private const val ED25519_PKCS8: String = RfcKeys.ED25519_PKCS8_PREFIX + RfcKeys.ED25519_SECRET

class SignatureTest : FunSpec({
    test("Ed25519 matches RFC 8032 test 1") {
        val secretKey = checkNotNull(
            crypto.keys.decodePrivate(SecretBytes.copyOf(hex(ED25519_PKCS8))).getOrNull(),
        )
        val publicKey = checkNotNull(
            crypto.keys.decodePublic(hex(RfcKeys.ED25519_SPKI_PREFIX + RfcKeys.ED25519_PUBLIC)).getOrNull(),
        )
        val signature = crypto.signatures.sign(key = secretKey, data = ByteString())
        hexOf(signature) shouldBe RfcKeys.ED25519_SIGNATURE
        crypto.signatures.verify(
            key = publicKey,
            data = ByteString(),
            signature = signature,
        ) shouldBe Verification.Valid
        crypto.signatures.verify(
            key = publicKey,
            data = utf8(MESSAGE),
            signature = signature,
        ) shouldBe Verification.Invalid
    }

    context("every family signs and verifies in both ECDSA formats") {
        withData(listOf(KeyType.Ed25519, KeyType.P256, KeyType.P384, KeyType.P521, KeyType.Rsa3072)) { type ->
            val pair = crypto.keys.generate(type)
            val der = crypto.signatures.sign(key = pair.privateKey, data = utf8(MESSAGE))
            val raw = crypto.signatures.sign(key = pair.privateKey, data = utf8(MESSAGE), format = SignatureFormat.Raw)
            crypto.signatures.verify(
                key = pair.publicKey,
                data = utf8(MESSAGE),
                signature = der,
            ) shouldBe Verification.Valid
            crypto.signatures.verify(
                key = pair.publicKey,
                data = utf8(MESSAGE),
                signature = raw,
                format = SignatureFormat.Raw,
            ) shouldBe
                Verification.Valid
            crypto.signatures.verify(
                key = pair.publicKey,
                data = utf8("other"),
                signature = der,
            ) shouldBe Verification.Invalid
            crypto.signatures.verify(
                key = pair.publicKey,
                data = utf8(MESSAGE),
                signature = ByteString(ByteArray(2)),
            ) shouldBe
                Verification.Invalid
        }
    }

    test("RSA signs with PSS by default and with PKCS #1 v1.5 where the policy permits it") {
        val pair = crypto.keys.generate(KeyType.Rsa3072)
        crypto.signatures.defaultFor(
            KeyFamily.Rsa,
            curve = null,
            bits = pair.publicKey.bits,
        ) shouldBe SignatureAlgorithm.RsaPssSha256
        shouldThrow<PolicyViolationException> {
            crypto.signatures.sign(
                key = pair.privateKey,
                data = utf8(MESSAGE),
                algorithm = SignatureAlgorithm.RsaPkcs1Sha256,
            )
        }
        val pss = crypto.signatures.sign(
            key = pair.privateKey,
            data = utf8(MESSAGE),
            algorithm = SignatureAlgorithm.RsaPssSha384,
        )
        crypto.signatures.verify(
            key = pair.publicKey,
            data = utf8(MESSAGE),
            signature = pss,
            algorithm = SignatureAlgorithm.RsaPssSha384,
        ) shouldBe Verification.Valid
    }

    test("a signer signs through the interface components use") {
        val pair = crypto.keys.generate(KeyType.P256)
        val signer = crypto.signatures.signer(pair.privateKey)
        signer.algorithm shouldBe SignatureAlgorithm.EcdsaSha256
        signer.publicKey shouldBe pair.publicKey
        signer.toString() shouldContain "ECDSA-SHA-256"
        val signature = signer.sign(utf8(MESSAGE))
        crypto.signatures.verify(
            key = pair.publicKey,
            data = utf8(MESSAGE),
            signature = signature,
        ) shouldBe Verification.Valid
    }

    test("a destroyed key and a wrong family are refused") {
        val pair = crypto.keys.generate(KeyType.Ed25519)
        shouldThrow<IllegalArgumentException> {
            crypto.signatures.sign(
                key = pair.privateKey,
                data = utf8(MESSAGE),
                algorithm = SignatureAlgorithm.EcdsaSha256,
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.signatures.verify(
                key = pair.publicKey,
                data = utf8(MESSAGE),
                signature = ByteString(),
                algorithm = SignatureAlgorithm.EcdsaSha256,
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.signatures.signer(
                key = pair.privateKey,
                algorithm = SignatureAlgorithm.Ed448,
            )
        }
        pair.privateKey.destroy()
        shouldThrow<IllegalStateException> { crypto.signatures.sign(key = pair.privateKey, data = utf8(MESSAGE)) }
    }

    test("the default algorithm fits every family that signs") {
        val signatures = crypto.signatures
        signatures.defaultFor(KeyFamily.Ed448, curve = null, bits = 0) shouldBe SignatureAlgorithm.Ed448
        signatures.defaultFor(KeyFamily.Ec, EllipticCurve.P384, bits = 0) shouldBe SignatureAlgorithm.EcdsaSha384
        signatures.defaultFor(KeyFamily.Ec, EllipticCurve.P521, bits = 0) shouldBe SignatureAlgorithm.EcdsaSha512
        signatures.defaultFor(KeyFamily.Ec, curve = null, bits = 0) shouldBe SignatureAlgorithm.EcdsaSha256
        signatures.defaultFor(KeyFamily.MlDsa, curve = null, bits = ML_DSA_44) shouldBe SignatureAlgorithm.MlDsa44
        signatures.defaultFor(KeyFamily.MlDsa, curve = null, bits = ML_DSA_87) shouldBe SignatureAlgorithm.MlDsa87
        listOf(KeyFamily.X25519, KeyFamily.X448, KeyFamily.MlKem).forEach { family ->
            shouldThrow<IllegalArgumentException> { signatures.defaultFor(family, curve = null, bits = 0) }
        }
    }

    test("the post-quantum and Ed448 signatures work where the platform has them") {
        val types = listOf(KeyType.Ed448, KeyType.MlDsa44, KeyType.MlDsa65, KeyType.MlDsa87)
        types.filter { type -> crypto.capabilities.supports(type) }.forEach { type ->
            val pair = crypto.keys.generate(type)
            val signature = crypto.signatures.sign(key = pair.privateKey, data = utf8(MESSAGE))
            crypto.signatures.verify(
                key = pair.publicKey,
                data = utf8(MESSAGE),
                signature = signature,
            ) shouldBe Verification.Valid
        }
    }
})
