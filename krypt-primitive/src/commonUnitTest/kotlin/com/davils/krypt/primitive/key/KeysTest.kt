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
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.fixture.OpenSslKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.fixture.hexOf
import com.davils.krypt.primitive.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.io.bytestring.ByteString

private const val RSA_BITS: Int = 2_048
private const val P256_BITS: Int = 256
private const val MESSAGE: String = "probe"
private const val SECRET_BITS: Int = 256
private const val DASHES: String = "-----"
private const val GARBAGE: String = "garbage"

private fun pem(label: String, hexDer: String): String = Pem.encode(label = label, bytes = hex(hexDer))

private fun privateLabel(prefix: String): String {
    val parts = listOf(prefix, "PRIVATE", "KEY")
    return parts.filter { part -> part.isNotEmpty() }.joinToString(" ")
}

class KeysTest : FunSpec({
    test("the keys of OpenSSL are read in every form") {
        val pkcs8 = checkNotNull(crypto.keys.decodePrivate(SecretBytes.copyOf(hex(OpenSslKeys.EC_PKCS8))).getOrNull())
        pkcs8.family shouldBe KeyFamily.Ec
        pkcs8.curve shouldBe EllipticCurve.P256
        pkcs8.bits shouldBe P256_BITS
        pkcs8.publicKey?.encoded shouldBe hex(OpenSslKeys.EC_SPKI)
        val sec1 = checkNotNull(
            crypto.keys.decodePrivatePem(pem(label = privateLabel("EC"), hexDer = OpenSslKeys.EC_SEC1)).getOrNull(),
        )
        sec1.publicKey shouldBe pkcs8.publicKey
        val rsa = checkNotNull(
            crypto.keys.decodePrivatePem(pem(label = privateLabel("RSA"), hexDer = OpenSslKeys.RSA_PKCS1)).getOrNull(),
        )
        rsa.bits shouldBe RSA_BITS
        rsa.publicKey?.encoded shouldBe hex(OpenSslKeys.RSA_SPKI)
        val rsaPublicPem = pem(label = "RSA PUBLIC KEY", hexDer = OpenSslKeys.RSA_PUBLIC_PKCS1)
        val rsaPublic = checkNotNull(crypto.keys.decodePublicPem(rsaPublicPem).getOrNull())
        rsaPublic.encoded shouldBe hex(OpenSslKeys.RSA_SPKI)
        val signature = crypto.signatures.sign(key = sec1, data = utf8(MESSAGE))
        crypto.signatures.verify(
            key = checkNotNull(pkcs8.publicKey),
            data = utf8(MESSAGE),
            signature = signature,
        ) shouldBe Verification.Valid
    }

    test("an encrypted key of OpenSSL is read with its password only") {
        val encrypted = pem(label = privateLabel("ENCRYPTED"), hexDer = OpenSslKeys.EC_ENCRYPTED)
        val key = fastCrypto.keys.decodePrivatePem(encrypted, SecretText.of(OpenSslKeys.PASSPHRASE)).getOrNull()
        key?.publicKey?.encoded shouldBe hex(OpenSslKeys.EC_SPKI)
        val wrong = fastCrypto.keys.decodePrivatePem(encrypted, SecretText.of("wrong"))
        wrong.failureOrNull() shouldBe KeyFailure.WrongPassword
        fastCrypto.keys.decodePrivatePem(encrypted).failureOrNull() shouldBe KeyFailure.PasswordRequired
        val strict = Crypto(environment { policy = CryptoPolicy.Modern })
        val tight = Crypto(
            environment {
                policy = cryptoPolicy { minimumVerifiedIterations = OpenSslKeys.ITERATIONS + 1 }
            },
        )
        strict.keys.decodePrivatePem(encrypted, SecretText.of(OpenSslKeys.PASSPHRASE)).isSuccess shouldBe true
        val refused = tight.keys.decodePrivatePem(encrypted, SecretText.of(OpenSslKeys.PASSPHRASE))
        refused.failureOrNull() shouldBe KeyFailure.Refused
    }

    test("keys are written and read back in PEM, encrypted or not") {
        val pair = fastCrypto.keys.generate(KeyType.Ed25519)
        val plain = fastCrypto.keys.encodePem(pair.privateKey)
        plain shouldContain "${DASHES}BEGIN ${privateLabel("")}$DASHES"
        fastCrypto.keys
            .decodePrivatePem(plain)
            .getOrNull()
            ?.family shouldBe KeyFamily.Ed25519
        val public = fastCrypto.keys.decodePublicPem(fastCrypto.keys.encodePem(pair.publicKey)).getOrNull()
        public shouldBe pair.publicKey
        val password = SecretText.of("correct horse")
        val encrypted = fastCrypto.keys.encryptPem(key = pair.privateKey, password = password)
        val decrypted = checkNotNull(fastCrypto.keys.decodePrivatePem(encrypted, password).getOrNull())
        checkNotNull(fastCrypto.keys.pair(decrypted, pair.publicKey)).publicKey shouldBe pair.publicKey
        val garbage = fastCrypto.keys.decrypt(utf8(GARBAGE), password)
        garbage.failureOrNull() shouldBe KeyFailure.UnsupportedEncryption
    }

    test("the legacy encryption of OpenSSL and texts without keys are refused") {
        val legacy = listOf(
            "${DASHES}BEGIN ${privateLabel("RSA")}$DASHES",
            "Proc-Type: 4,ENCRYPTED",
            "DEK-Info: AES-256-CBC,00",
            "",
            "AQID",
            "${DASHES}END ${privateLabel("RSA")}$DASHES",
        ).joinToString("\n")
        crypto.keys.decodePrivatePem(legacy).failureOrNull() shouldBe KeyFailure.UnsupportedEncryption
        crypto.keys.decodePrivatePem("no key").failureOrNull() shouldBe KeyFailure.Malformed
        crypto.keys.decodePrivatePem("$DASHES${"BEGIN"} A").failureOrNull() shouldBe KeyFailure.Malformed
        crypto.keys.decodePublicPem("no key").failureOrNull() shouldBe KeyFailure.Malformed
        crypto.keys.decodePublicPem("${DASHES}BEGIN X$DASHES").failureOrNull() shouldBe KeyFailure.Malformed
        val broken = crypto.keys.decodePrivatePem(pem(label = privateLabel("EC"), hexDer = "3003020101"))
        broken.failureOrNull() shouldBe KeyFailure.Malformed
    }

    test("malformed, unknown and forbidden keys are refused") {
        crypto.keys.decodePublic(utf8(GARBAGE)) shouldBe Outcome.Failure(KeyFailure.Malformed)
        crypto.keys.decodePublic(
            hex("300d300706032a03040500030200ff"),
        ) shouldBe Outcome.Failure(KeyFailure.UnsupportedAlgorithm)
        crypto.keys.decodePrivate(SecretBytes.copyOf(utf8(GARBAGE))) shouldBe Outcome.Failure(KeyFailure.Malformed)
        val cnsa = Crypto(environment { policy = CryptoPolicy.Cnsa2 })
        cnsa.keys.decodePublic(hex(OpenSslKeys.EC_SPKI)) shouldBe Outcome.Failure(KeyFailure.Refused)
        cnsa.keys.decodePublic(hex(OpenSslKeys.RSA_SPKI)) shouldBe Outcome.Failure(KeyFailure.Refused)
        shouldThrow<PolicyViolationException> { cnsa.keys.generate(KeyType.P256) }
    }

    test("private keys hide their material and can be destroyed") {
        val pair = crypto.keys.generate(KeyType.P256)
        val text = pair.privateKey.toString()
        text shouldNotContain hexOf(crypto.keys.encodePrivate(pair.privateKey).reveal { bytes -> ByteString(bytes) })
        pair.privateKey.isExtractable shouldBe true
        pair.privateKey shouldNotBe crypto.keys.generate(KeyType.P256).privateKey
        pair.privateKey.hashCode() shouldBe pair.privateKey.hashCode()
        pair.toString() shouldContain "PublicKey(Ec"
        pair shouldBe KeyPair(publicKey = pair.publicKey, privateKey = pair.privateKey)
        pair.hashCode() shouldBe pair.publicKey.hashCode()
        pair.publicKey.toString() shouldBe "PublicKey(Ec, curve=P-256, bits=256)"
        pair.privateKey.destroy()
        pair.privateKey.isDestroyed shouldBe true
        shouldThrow<IllegalStateException> { crypto.keys.encodePrivate(pair.privateKey) }
    }

    test("symmetric keys are random, comparable in constant time and exportable") {
        val key = crypto.keys.generateSecret()
        key.bits shouldBe SECRET_BITS
        key shouldNotBe crypto.keys.generateSecret()
        key shouldBe SecretKey.of(key.export())
        key.hashCode() shouldBe SECRET_BITS
        key.toString() shouldBe "SecretKey(bits=256, key=****, destroyed=false)"
        shouldThrow<IllegalArgumentException> { crypto.keys.generateSecret(1) }
        shouldThrow<IllegalArgumentException> { SecretKey.of(SecretBytes.copyOf(hex("00"))) }
        key.destroy()
        key.isDestroyed shouldBe true
    }

    test("a pair is formed only of keys that belong together") {
        val first = crypto.keys.generate(KeyType.X25519)
        val second = crypto.keys.generate(KeyType.X25519)
        crypto.keys.pair(first.privateKey, first.publicKey) shouldNotBe null
        crypto.keys.pair(first.privateKey, second.publicKey) shouldBe null
        val signing = crypto.keys.generate(KeyType.Ed25519)
        crypto.keys.pair(signing.privateKey, crypto.keys.generate(KeyType.Ed25519).publicKey) shouldBe null
        shouldThrow<IllegalArgumentException> { crypto.keys.pair(first.privateKey, signing.publicKey) }
        crypto.keys.fingerprint(signing.publicKey).size shouldBe P256_BITS / Byte.SIZE_BITS
    }
})
