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

package com.davils.krypt.cose

import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.KeyWrapAlgorithm
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicyBuilder
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.cose.cbor.CborMode
import com.davils.krypt.cose.fixture.CONTENT
import com.davils.krypt.cose.fixture.RSA_PSS_01
import com.davils.krypt.cose.fixture.RSA_PSS_01_KEY_0
import com.davils.krypt.cose.fixture.cose
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.key
import com.davils.krypt.cose.fixture.relaxed
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.primitive.Crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private val EVERYTHING: Set<CoseAlgorithm> = CoseAlgorithm.entries.toSet()

private fun restricted(configure: CryptoPolicyBuilder.() -> Unit): Cose =
    Cose(Crypto(environment { policy = cryptoPolicy(configure = configure) }))

class PolicyTest : FunSpec({
    test("the policy decides which signatures and keys verify") {
        val edwards = crypto.keys.generate(KeyType.Ed25519)
        val polymorphic = cose.sign1(
            payload = utf8(CONTENT),
            signer = CoseSigner(key = CoseKey.of(edwards.privateKey), algorithm = CoseAlgorithm.EdDsa),
        )
        val specified = cose.sign1(
            payload = utf8(CONTENT),
            signer = CoseSigner(key = CoseKey.of(edwards.privateKey), algorithm = CoseAlgorithm.Ed25519),
        )
        val withoutEdwards = restricted { forbid(SignatureAlgorithm.Ed25519) }
        val verifier = listOf(CoseKey.of(edwards.publicKey))
        val outcome1 = withoutEdwards.verify(
            message = polymorphic,
            keys = verifier,
            algorithms = EVERYTHING,
        )
        outcome1.failure() shouldBe CoseFailure.InvalidSignature
        val outcome2 = withoutEdwards.verify(
            message = specified,
            keys = verifier,
            algorithms = EVERYTHING,
        )
        outcome2.failure() shouldBe CoseFailure.AlgorithmNotPermitted
        val p384 = crypto.keys.generate(KeyType.P384)
        val curved = cose.sign1(
            payload = utf8(CONTENT),
            signer = CoseSigner(key = CoseKey.of(p384.privateKey), algorithm = CoseAlgorithm.Esp384),
        )
        val onlyP256 = restricted { curves(EllipticCurve.P256) }
        val outcome3 = onlyP256.verify(
            message = curved,
            keys = listOf(CoseKey.of(p384.publicKey)),
            algorithms = EVERYTHING,
        )
        outcome3.failure() shouldBe
            CoseFailure.InvalidSignature
        val pss = relaxed.decodeSign(hex(RSA_PSS_01)).value()
        val bigRsa = restricted { minimumVerifiedRsaBits = KeyType.Rsa3072.bits }
        val relaxedBig = Cose(crypto = bigRsa.crypto, mode = CborMode.Relaxed)
        val outcome4 = relaxedBig.verify(
            message = pss,
            keys = listOf(key(RSA_PSS_01_KEY_0)),
            algorithms = EVERYTHING,
        )
        outcome4.failure() shouldBe
            CoseFailure.InvalidSignature
    }

    test("an ECDSA signature of the wrong size never verifies") {
        val pair = crypto.keys.generate(KeyType.P256)
        val message = cose.sign1(
            payload = utf8(CONTENT),
            signer = CoseSigner(key = CoseKey.of(pair.privateKey), algorithm = CoseAlgorithm.Esp256),
        )
        val short = CoseSign1(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            payload = message.payload,
            signature = message.signature.substring(startIndex = 1, endIndex = message.signature.size),
            protectedEncoding = message.protectedEncoding,
        )
        val outcome5 = cose.verify(
            message = short,
            keys = listOf(CoseKey.of(pair.publicKey)),
            algorithms = EVERYTHING,
        )
        outcome5.failure() shouldBe
            CoseFailure.InvalidSignature
    }

    test("the policy decides which recipients give a key") {
        val pair = crypto.keys.generate(KeyType.P256)
        val agreement = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(
                CoseRecipientSpec(key = CoseKey.of(pair.publicKey), algorithm = CoseAlgorithm.EcdhEsHkdf256),
            ),
        )
        val withoutEcdh = restricted { forbid(KeyAgreementAlgorithm.EcdhP256) }
        val outcome6 = withoutEcdh.decrypt(
            message = agreement,
            keys = listOf(CoseKey.of(pair.privateKey)),
            algorithms = EVERYTHING,
        )
        outcome6.failure() shouldBe
            CoseFailure.DecryptionFailed
        val wrapKey = CoseKey.of(crypto.keys.generateSecret(16))
        val wrapped = cose.encrypt(
            plaintext = utf8(CONTENT),
            algorithm = CoseAlgorithm.A128Gcm,
            recipients = listOf(CoseRecipientSpec(key = wrapKey, algorithm = CoseAlgorithm.A128Kw)),
        )
        val withoutWrap = restricted { forbid(KeyWrapAlgorithm.Aes128Kw) }
        val outcome7 = withoutWrap.decrypt(
            message = wrapped,
            keys = listOf(wrapKey),
            algorithms = EVERYTHING,
        )
        outcome7.failure() shouldBe CoseFailure.AlgorithmNotPermitted
    }
})
