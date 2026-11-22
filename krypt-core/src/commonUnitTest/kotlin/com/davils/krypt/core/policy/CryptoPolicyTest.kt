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

@file:OptIn(LegacyCryptography::class)

package com.davils.krypt.core.policy

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private const val RSA_2048: Int = 2_048
private const val RSA_3072: Int = 3_072
private const val RSA_1024: Int = 1_024
private const val RSA_HUGE: Int = 16_384
private const val ITERATIONS: Int = 600_000
private const val FEW_ITERATIONS: Int = 2_048

class CryptoPolicyTest : FunSpec({
    test("the modern profile permits current algorithms and verifies PKCS #1 signatures only") {
        val policy = CryptoPolicy.Modern
        policy.profile shouldBe CryptoProfile.Modern
        policy.permits(SignatureAlgorithm.Ed25519, AlgorithmUse.Protect) shouldBe true
        policy.permits(SignatureAlgorithm.RsaPkcs1Sha256, AlgorithmUse.Protect) shouldBe false
        policy.permits(SignatureAlgorithm.RsaPkcs1Sha256, AlgorithmUse.Verify) shouldBe true
        policy.permits(DigestAlgorithm.Sha1, AlgorithmUse.Verify) shouldBe false
        policy.permitsRsa(RSA_2048, AlgorithmUse.Protect) shouldBe false
        policy.permitsRsa(RSA_2048, AlgorithmUse.Verify) shouldBe true
        policy.permitsRsa(RSA_HUGE, AlgorithmUse.Verify) shouldBe false
        policy.permitsIterations(ITERATIONS, AlgorithmUse.Protect) shouldBe true
        policy.permitsIterations(FEW_ITERATIONS, AlgorithmUse.Protect) shouldBe false
        policy.permitsIterations(FEW_ITERATIONS, AlgorithmUse.Verify) shouldBe true
        policy.permitsIterations(CryptoPolicy.HARD_MAXIMUM_ITERATIONS, AlgorithmUse.Verify) shouldBe false
        policy.permitsCurve(EllipticCurve.P521) shouldBe true
        policy.isFipsProviderRequired shouldBe false
    }

    test("the compatible profile permits 2048-bit RSA and PKCS #1 signatures for new work") {
        val policy = CryptoPolicy.Compatible
        policy.permitsRsa(RSA_2048, AlgorithmUse.Protect) shouldBe true
        policy.permits(SignatureAlgorithm.RsaPkcs1Sha256, AlgorithmUse.Protect) shouldBe true
    }

    test("the CNSA 2.0 profile keeps to the suite") {
        val policy = CryptoPolicy.Cnsa2
        policy.permits(KemAlgorithm.MlKem1024, AlgorithmUse.Protect) shouldBe true
        policy.permits(SignatureAlgorithm.MlDsa87, AlgorithmUse.Protect) shouldBe true
        policy.permits(SignatureAlgorithm.EcdsaSha384, AlgorithmUse.Protect) shouldBe true
        policy.permits(AeadAlgorithm.Aes256Gcm, AlgorithmUse.Protect) shouldBe true
        policy.permits(AeadAlgorithm.Aes128Gcm, AlgorithmUse.Verify) shouldBe false
        policy.permits(SignatureAlgorithm.Ed25519, AlgorithmUse.Verify) shouldBe false
        policy.permits(DigestAlgorithm.Sha256, AlgorithmUse.Protect) shouldBe false
        policy.permitsCurve(EllipticCurve.P256) shouldBe false
        policy.permitsRsa(RSA_2048, AlgorithmUse.Verify) shouldBe false
    }

    test("the CNSA 2.0 profile protects with exactly the suite and verifies RSA signatures only") {
        val policy = CryptoPolicy.Cnsa2
        policy.protecting shouldBe setOf(
            AeadAlgorithm.Aes256Gcm,
            KeyWrapAlgorithm.Aes256Kw,
            DigestAlgorithm.Sha384,
            DigestAlgorithm.Sha512,
            MacAlgorithm.HmacSha384,
            MacAlgorithm.HmacSha512,
            KdfAlgorithm.HkdfSha384,
            KdfAlgorithm.HkdfSha512,
            KdfAlgorithm.Pbkdf2Sha512,
            KemAlgorithm.MlKem1024,
            KemAlgorithm.DhkemP384,
            SignatureAlgorithm.MlDsa87,
            SignatureAlgorithm.EcdsaSha384,
            KeyAgreementAlgorithm.EcdhP384,
        )
        policy.verifying - policy.protecting shouldBe setOf(
            SignatureAlgorithm.RsaPssSha384,
            SignatureAlgorithm.RsaPssSha512,
            SignatureAlgorithm.RsaPkcs1Sha384,
            SignatureAlgorithm.RsaPkcs1Sha512,
        )
        policy.permits(MacAlgorithm.HmacSha256, AlgorithmUse.Verify) shouldBe false
        policy.permits(KdfAlgorithm.HkdfSha256, AlgorithmUse.Protect) shouldBe false
        policy.permits(KdfAlgorithm.Pbkdf2Sha256, AlgorithmUse.Protect) shouldBe false
        policy.permits(DigestAlgorithm.Sha3384, AlgorithmUse.Protect) shouldBe false
        policy.permits(SignatureAlgorithm.RsaPssSha384, AlgorithmUse.Protect) shouldBe false
        policy.permits(AsymmetricEncryptionAlgorithm.RsaOaepSha384, AlgorithmUse.Verify) shouldBe false
        policy.permitsRsa(RSA_3072, AlgorithmUse.Verify) shouldBe true
    }

    test("the FIPS profile permits approved algorithms and demands a validated provider") {
        val policy = CryptoPolicy.Fips
        policy.isFipsProviderRequired shouldBe true
        policy.permits(KeyAgreementAlgorithm.X25519, AlgorithmUse.Verify) shouldBe false
        policy.permits(AeadAlgorithm.ChaCha20Poly1305, AlgorithmUse.Protect) shouldBe false
        policy.permits(KeyAgreementAlgorithm.EcdhP256, AlgorithmUse.Protect) shouldBe true
    }

    test("a custom policy permits, accepts, forbids and restricts curves") {
        val policy = cryptoPolicy {
            forbid(SignatureAlgorithm.Ed25519)
            accept(SignatureAlgorithm.RsaPkcs1Sha512)
            acceptLegacy(DigestAlgorithm.Sha1)
            permit(SignatureAlgorithm.RsaPkcs1Sha256)
            curves(EllipticCurve.P384)
            minimumRsaBits = RSA_2048
            minimumVerifiedRsaBits = RSA_2048
            maximumRsaBits = RSA_3072
            minimumIterations = FEW_ITERATIONS
            minimumVerifiedIterations = FEW_ITERATIONS
            maximumIterations = ITERATIONS
            isFipsProviderRequired = true
        }
        policy.permits(SignatureAlgorithm.Ed25519, AlgorithmUse.Verify) shouldBe false
        policy.permits(SignatureAlgorithm.RsaPkcs1Sha512, AlgorithmUse.Protect) shouldBe false
        policy.permits(SignatureAlgorithm.RsaPkcs1Sha512, AlgorithmUse.Verify) shouldBe true
        policy.permits(DigestAlgorithm.Sha1, AlgorithmUse.Verify) shouldBe true
        policy.permits(SignatureAlgorithm.RsaPkcs1Sha256, AlgorithmUse.Protect) shouldBe true
        policy.curves shouldBe setOf(EllipticCurve.P384)
        policy.maximumRsaBits shouldBe RSA_3072
        policy.minimumIterations shouldBe FEW_ITERATIONS
        policy.maximumIterations shouldBe ITERATIONS
        policy.isFipsProviderRequired shouldBe true
        policy.toString() shouldContain "profile=Modern"
    }

    test("legacy algorithms are never permitted or accepted without the legacy opt-in") {
        shouldThrow<IllegalArgumentException> { cryptoPolicy { permit(DigestAlgorithm.Sha1) } }
        shouldThrow<IllegalArgumentException> { cryptoPolicy { accept(SignatureAlgorithm.RsaPkcs1Sha1) } }
    }

    test("bounds outside the hard ceilings or out of order are refused") {
        shouldThrow<ValidationException> { cryptoPolicy { minimumVerifiedRsaBits = RSA_1024 } }
        shouldThrow<ValidationException> { cryptoPolicy { maximumRsaBits = RSA_HUGE + 1 } }
        shouldThrow<ValidationException> { cryptoPolicy { minimumRsaBits = RSA_2048 - 1 } }
        shouldThrow<ValidationException> {
            cryptoPolicy { maximumIterations = CryptoPolicy.HARD_MAXIMUM_ITERATIONS + 1 }
        }
        shouldThrow<ValidationException> { cryptoPolicy { minimumVerifiedIterations = ITERATIONS + 1 } }
        shouldThrow<ValidationException> { cryptoPolicy { minimumIterations = 0 } }
    }

    test("a built policy builder refuses further changes") {
        val builder = CryptoPolicyBuilder(CryptoProfile.Modern)
        builder.build()
        builder.profile shouldBe CryptoProfile.Modern
        shouldThrow<IllegalStateException> { builder.minimumRsaBits = RSA_3072 }
        shouldThrow<IllegalStateException> { builder.forbid(DigestAlgorithm.Sha256) }
    }
})
