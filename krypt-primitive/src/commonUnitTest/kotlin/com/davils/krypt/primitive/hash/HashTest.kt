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

package com.davils.krypt.primitive.hash

import com.davils.krypt.core.LegacyCryptography
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.fixture.hexOf
import com.davils.krypt.primitive.fixture.secret
import com.davils.krypt.primitive.fixture.utf8
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val ABC: String = "abc"
private const val HKDF_LENGTH: Int = 42
private const val PBKDF2_LENGTH: Int = 64
private const val SALT_LENGTH: Int = 16
private const val KEY_LENGTH: Int = 32
private const val ITERATIONS: Int = 1_000
private const val PASSWORD: String = "passwd"
private const val HI_THERE: String = "Hi There"

private fun hashInPieces(digester: Digester): ByteString {
    digester.update(utf8("a"))
    digester.update(bytes = ABC.encodeToByteArray(), offset = 1, length = 2)
    return digester.finish()
}

class HashTest : FunSpec({
    context("SHA-2 of abc matches FIPS 180-4") {
        withData(
            listOf(
                DigestAlgorithm.Sha256 to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                DigestAlgorithm.Sha384 to
                    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
                DigestAlgorithm.Sha512 to
                    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd" +
                    "454d4423643ce80e2a9ac94fa54ca49f",
            ),
        ) { (algorithm, expected) ->
            hexOf(
                crypto.digests.digest(data = utf8(ABC), algorithm = algorithm),
            ) shouldBe expected
        }
    }

    test("a digester hashes input in pieces where the platform supports it") {
        val digester = crypto.digests.digester()
        val whole = crypto.digests.digest(utf8(ABC))
        digester?.let { found -> hashInPieces(found) shouldBe whole }
        (digester == null) shouldBe !crypto.capabilities.hasIncrementalDigest
    }

    test("HMAC-SHA-256 matches RFC 4231 test case 1 and verifies in constant time") {
        val key = SecretKey.adopt(secret("0b".repeat(20)))
        val tag = crypto.macs.mac(key = key, data = utf8(HI_THERE))
        hexOf(tag) shouldBe "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        crypto.macs.verify(key = key, data = utf8(HI_THERE), tag = tag) shouldBe Verification.Valid
        crypto.macs.verify(key = key, data = utf8("Hi there"), tag = tag) shouldBe Verification.Invalid
        crypto.macs.verify(key = key, data = utf8(HI_THERE), tag = ByteString()) shouldBe Verification.Invalid
        crypto.macs.mac(key = key, data = utf8(ABC), algorithm = MacAlgorithm.HmacSha512).size shouldBe PBKDF2_LENGTH
    }

    test("HKDF matches RFC 5869 test case 1") {
        val okm = crypto.derivations.hkdf(
            inputKey = secret("0b".repeat(22)),
            salt = hex("000102030405060708090a0b0c"),
            info = hex("f0f1f2f3f4f5f6f7f8f9"),
            length = HKDF_LENGTH,
        )
        hexOf(okm.reveal { bytes -> ByteString(bytes) }) shouldBe
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        val zeroSalt = crypto.derivations.hkdf(
            inputKey = secret("0b".repeat(22)),
            salt = ByteString(),
            info = ByteString(),
            length = HKDF_LENGTH,
        )
        zeroSalt.reveal { bytes -> hexOf(ByteString(bytes)) } shouldBe
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    }

    test("HKDF refuses impossible lengths, short keys and password derivations") {
        val prk = secret("00".repeat(KEY_LENGTH))
        shouldThrow<IllegalArgumentException> {
            crypto.derivations.expand(
                pseudorandomKey = prk,
                info = ByteString(),
                length = 0,
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.derivations.expand(pseudorandomKey = prk, info = ByteString(), length = 255 * KEY_LENGTH + 1)
        }
        shouldThrow<IllegalArgumentException> {
            crypto.derivations.expand(
                pseudorandomKey = secret("00"),
                info = ByteString(),
                length = 1,
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.derivations.extract(salt = ByteString(), inputKey = prk, algorithm = KdfAlgorithm.Pbkdf2Sha256)
        }
    }

    test("PBKDF2 matches RFC 7914 section 11 and keeps to the policy") {
        val derived = crypto.backend.pbkdf2(
            digest = DigestAlgorithm.Sha256,
            password = SecretText.of(PASSWORD),
            salt = utf8("salt").toByteArray(),
            iterations = 1,
            length = PBKDF2_LENGTH,
        )
        hexOf(ByteString(derived)) shouldBe "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" +
            "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        val salt = ByteString(ByteArray(SALT_LENGTH))
        val key = fastCrypto.derivations.pbkdf2(
            password = SecretText.of(PASSWORD),
            salt = salt,
            iterations = ITERATIONS,
            length = KEY_LENGTH,
        )
        key.size shouldBe KEY_LENGTH
        shouldThrow<PolicyViolationException> {
            crypto.derivations.pbkdf2(
                password = SecretText.of(PASSWORD),
                salt = salt,
                iterations = ITERATIONS,
                length = KEY_LENGTH,
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.derivations.pbkdf2(
                password = SecretText.of(PASSWORD),
                salt = ByteString(),
                iterations = ITERATIONS,
                length = KEY_LENGTH,
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.derivations.pbkdf2(
                password = SecretText.of(PASSWORD),
                salt = salt,
                iterations = ITERATIONS,
                length = 1,
            )
        }
        shouldThrow<IllegalArgumentException> {
            crypto.derivations.pbkdf2(
                password = SecretText.of(PASSWORD),
                salt = salt,
                iterations = ITERATIONS,
                length = KEY_LENGTH,
                algorithm = KdfAlgorithm.HkdfSha256,
            )
        }
        val verified = fastCrypto.derivations.pbkdf2(
            password = SecretText.of(PASSWORD),
            salt = salt,
            iterations = ITERATIONS,
            length = KEY_LENGTH,
            use = AlgorithmUse.Verify,
        )
        verified.size shouldBe KEY_LENGTH
    }

    test("legacy digests are refused unless the policy accepts them for verification") {
        shouldThrow<PolicyViolationException> {
            crypto.digests.digest(
                data = utf8(ABC),
                algorithm = DigestAlgorithm.Sha1,
            )
        }
        shouldThrow<PolicyViolationException> { crypto.digests.digester(algorithm = DigestAlgorithm.Md5) }
    }
})
