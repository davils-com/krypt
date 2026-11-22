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

package com.davils.krypt.cose.key

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseLimits
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborMode
import com.davils.krypt.cose.fixture.RSA_PSS_01_KEY_0
import com.davils.krypt.cose.fixture.coseKeys
import com.davils.krypt.cose.fixture.crypto
import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.hexOf
import com.davils.krypt.cose.fixture.key
import com.davils.krypt.cose.fixture.utf8
import com.davils.krypt.cose.fixture.value
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.io.bytestring.ByteString

private const val THUMBPRINT_KEY: String =
    "A50102200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D2258201E52ED75701163F7F9" +
        "E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C025820496BD8AFADF307E5B08C64B0421BF9DC01528A344A43BDA88FA" +
        "DD1669DA253EC"
private const val THUMBPRINT: String = "496BD8AFADF307E5B08C64B0421BF9DC01528A344A43BDA88FADD1669DA253EC"
private const val P256_X: String = "65EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D"
private const val P256_Y: String = "1E52ED75701163F7F9E40DDF9F341B3DC9BA860AF7E0CA7CA7E9EECD0084D19C"
private const val KID: String = "kid"
private const val X_LABEL: Long = -2

private const val POINT: String = "215820" + P256_X + "225820" + P256_Y
private const val EC_POINT: String = "2001$POINT"

private suspend fun roundTrips(type: KeyType) {
    val pair = crypto.keys.generate(type)
    val key = CoseKey.of(pair.privateKey, keyId = utf8(KID), operations = setOf(CoseKeyOperation.Sign))
    val public = coseKeys.decode(coseKeys.encode(key)).value()
    public.publicKey shouldBe pair.publicKey
    public.privateKey shouldBe null
    public.keyId shouldBe utf8(KID)
    public.operations shouldBe setOf(CoseKeyOperation.Sign)
    val outcome1 = coseKeys.encodePrivate(
        key,
    )
    val private = outcome1.use { encoded -> encoded.reveal { bytes -> coseKeys.decode(ByteString(bytes)) } }
    private.value().publicKey shouldBe pair.publicKey
    crypto.keys.pair(checkNotNull(private.value().privateKey), pair.publicKey) shouldNotBe null
}

class CoseKeysTest : FunSpec({
    test("the thumbprint of RFC 9679 matches its example") {
        coseKeys.decode(hex(THUMBPRINT_KEY)).failure() shouldBe CoseFailure.Malformed
        val relaxed = CoseKeys(crypto = crypto, mode = CborMode.Relaxed)
        val key = relaxed.decode(hex(THUMBPRINT_KEY)).value()
        hexOf(coseKeys.thumbprint(key)) shouldBe THUMBPRINT
        coseKeys.thumbprint(key, DigestAlgorithm.Sha512).size shouldBe DigestAlgorithm.Sha512.outputBytes
    }

    test("keys of every type round-trip with and without their private part") {
        listOf(KeyType.P256, KeyType.P384, KeyType.P521, KeyType.Ed25519, KeyType.X25519).forEach { type ->
            roundTrips(type)
        }
        val optional = listOf(KeyType.Ed448, KeyType.X448).filter { type -> crypto.capabilities.supports(type) }
        optional.forEach { type ->
            roundTrips(type)
        }
        val rsa = key(RSA_PSS_01_KEY_0)
        val encoded = coseKeys.encodePrivate(rsa).use { bytes -> bytes.reveal { raw -> hexOf(ByteString(raw)) } }
        encoded shouldBe RSA_PSS_01_KEY_0
        coseKeys.decode(coseKeys.encode(rsa)).value().publicKey shouldBe rsa.publicKey
        val secret = CoseKey.of(crypto.keys.generateSecret(), keyId = utf8(KID), algorithm = CoseAlgorithm.A256Gcm)
        val decoded = coseKeys.encodePrivate(secret).use { bytes ->
            bytes.reveal { raw -> coseKeys.decode(ByteString(raw)) }
        }
        decoded.value() shouldBe secret
        coseKeys.thumbprint(secret).size shouldBe DigestAlgorithm.Sha256.outputBytes
        shouldThrow<IllegalArgumentException> { coseKeys.encode(secret) }
    }

    test("key sets round-trip and find keys by id") {
        val first = CoseKey.of(crypto.keys.generate(KeyType.P256).publicKey, keyId = utf8(KID))
        val second = CoseKey.of(crypto.keys.generate(KeyType.Ed25519).publicKey, keyId = utf8("other"))
        val set = CoseKeySet(listOf(first, second))
        val decoded = coseKeys.decodeSet(coseKeys.encodeSet(set)).value()
        decoded shouldBe set
        decoded.hashCode() shouldBe set.hashCode()
        decoded.withKeyId(utf8(KID)) shouldBe listOf(first)
        decoded.toString() shouldContain "CoseKeySet"
        decoded.equals(KID) shouldBe false
        shouldThrow<IllegalArgumentException> {
            coseKeys.encodeSet(CoseKeySet(listOf(CoseKey.of(crypto.keys.generateSecret()))))
        }
        val bounded = CoseKeys(crypto = crypto, limits = CoseLimits(maximumKeys = 1))
        bounded.decodeSet(coseKeys.encodeSet(set)).failure() shouldBe CoseFailure.Malformed
        coseKeys.decodeSet(hex("A0")).failure() shouldBe CoseFailure.Malformed
        coseKeys.decodeSet(hex("8100")).failure() shouldBe CoseFailure.Malformed
        coseKeys.decodeSet(hex("FF")).failure() shouldBe CoseFailure.Malformed
        bounded.toString() shouldContain "CoseKeys"
    }

    test("hostile keys are refused") {
        val malformed = listOf(
            "FF",
            "80",
            "A0",
            "A201022001",
            "A30102200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D",
            "A40102200121581F" + P256_X.drop(2) + "225820" + P256_Y,
            "A10104",
            "A201042001",
            "A2010320480101010101010101",
            "A501020401$EC_POINT",
            "A501020540$EC_POINT",
            "A501020201$EC_POINT",
            "A401032048C1C1C1C1C1C1C1C1214301000122480505050505050505",
            "A30102$POINT",
        )
        malformed.forEach { encoded -> coseKeys.decode(hex(encoded)).failure() shouldBe CoseFailure.Malformed }
        val unsupported = listOf(
            "A10163454332",
            "A10109",
            "A401022004$POINT",
            "A401022008$POINT",
            "A401022065502D323536$POINT",
            "A40102200121582065EDA5A12577C2BAE829437FE338701A10AAA375E1BB5B5DE108DE439C08551D22F5",
            "A20104204A00000000000000000000",
            "A50102033A00010000$EC_POINT",
            "A5010203656F74686572$EC_POINT",
            "A501020301$EC_POINT",
            "A5010204810B$EC_POINT",
            "A501020481647369676E$EC_POINT",
            "A401032048C1C1C1C1C1C1C1C121430100012880",
        )
        unsupported.forEach { encoded -> coseKeys.decode(hex(encoded)).failure() shouldBe CoseFailure.UnsupportedKey }
    }

    test("keys show their public parts only and compare by every part") {
        val pair = crypto.keys.generate(KeyType.P256)
        val key = CoseKey.of(pair.privateKey, keyId = utf8(KID), algorithm = CoseAlgorithm.Esp256)
        key.toString() shouldContain "private=****"
        key.toString() shouldContain "ESP256"
        key.toString() shouldNotContain "null"
        val public = CoseKey.of(pair.publicKey)
        public.toString() shouldContain "private=none"
        public.toString() shouldContain "keyId=none"
        public.toString() shouldContain "algorithm=none"
        key shouldNotBe public
        key shouldBe CoseKey.of(pair.privateKey, keyId = utf8(KID), algorithm = CoseAlgorithm.Esp256)
        val same = CoseKey.of(pair.privateKey, keyId = utf8(KID), algorithm = CoseAlgorithm.Esp256)
        key.hashCode() shouldBe same.hashCode()
        key.equals(KID) shouldBe false
        val other = crypto.keys.generate(KeyType.P256).privateKey
        key shouldNotBe CoseKey.of(other, keyId = utf8(KID), algorithm = CoseAlgorithm.Esp256)
        val secret = crypto.keys.generateSecret()
        CoseKey.of(secret) shouldNotBe CoseKey.of(crypto.keys.generateSecret())
        CoseKey.of(secret) shouldBe CoseKey.of(secret)
        shouldThrow<IllegalArgumentException> { CoseKey.of(pair.publicKey, algorithm = CoseAlgorithm.Ed25519) }
        shouldThrow<IllegalArgumentException> { CoseKey.of(secret, algorithm = CoseAlgorithm.Esp256) }
        shouldThrow<IllegalArgumentException> {
            CoseKey.of(pair.privateKey, publicKey = crypto.keys.generate(KeyType.P384).publicKey)
        }
        shouldThrow<IllegalArgumentException> {
            CoseKey.of(pair.privateKey, publicKey = crypto.keys.generate(KeyType.Ed25519).publicKey)
        }
        val noCose = KeyType.MlDsa44.takeIf { type -> crypto.capabilities.supports(type) }
        noCose?.let { type ->
            shouldThrow<IllegalArgumentException> { CoseKey.of(crypto.keys.generate(type).publicKey) }
        }
        CoseKey.of(pair.privateKey, publicKey = null).publicKey shouldBe null
        coseKeys.decode(coseKeys.encode(CoseKey.of(pair.privateKey))).getOrNull()?.publicKey shouldBe pair.publicKey
        CoseKeyType.entries.map { type -> type.id } shouldBe List(size = 4) { index -> index + 1L }
        CoseKeyOperation.entries.map { operation -> operation.id } shouldBe List(size = 10) { index -> index + 1L }
        CoseCurve.entries.map { curve -> curve.id } shouldBe List(size = 7) { index -> index + 1L }
    }

    test("private keys without their public part encode and decode") {
        listOf(KeyType.P256, KeyType.Ed25519).forEach { type ->
            val pair = crypto.keys.generate(type)
            val full = coseKeys.encodePrivate(CoseKey.of(pair.privateKey)).use { bytes ->
                bytes.reveal { raw -> Cbor.decode(ByteString(raw)).value() as CborMap }
            }
            val privateOnly = CborMap(
                full.entries.filter { (label, _) -> label != CborInteger.of(-2) && label != CborInteger.of(-3) },
            )
            val key = coseKeys.decode(Cbor.encode(privateOnly)).value()
            key.publicKey shouldBe null
            checkNotNull(key.privateKey).publicKey shouldBe null
            val public = Cbor.decode(coseKeys.encode(key)).value() as CborMap
            public[X_LABEL] shouldBe null
            val again = coseKeys.encodePrivate(key).use { bytes -> bytes.reveal { raw -> ByteString(raw) } }
            Cbor.decode(again).value() shouldBe privateOnly
            val curveOnly = CborMap(privateOnly.entries.filter { (label, _) -> label != CborInteger.of(-4) })
            coseKeys.decode(Cbor.encode(curveOnly)).failure() shouldBe CoseFailure.Malformed
        }
        val pair = crypto.keys.generate(KeyType.P384)
        val viaPrivate = CoseKey.of(pair.privateKey, publicKey = null)
        coseKeys.decode(coseKeys.encode(viaPrivate)).value().publicKey shouldBe pair.publicKey
        val publicOnly = CoseKey.of(pair.publicKey)
        val encoded = coseKeys.encodePrivate(publicOnly).use { bytes -> bytes.reveal { raw -> ByteString(raw) } }
        encoded shouldBe coseKeys.encode(publicOnly)
        val baseIv = hex("000102030405060708090A0B")
        val secret = CoseKey.of(crypto.keys.generateSecret(16), baseIv = baseIv)
        val symmetric = coseKeys.encodePrivate(secret).use { bytes -> bytes.reveal { raw -> ByteString(raw) } }
        coseKeys.decode(symmetric).value().baseIv shouldBe baseIv
        shouldThrow<IllegalArgumentException> { CoseKey.of(pair.publicKey, algorithm = CoseAlgorithm.Hmac256) }
        shouldThrow<IllegalArgumentException> { CoseKey.of(pair.publicKey, algorithm = CoseAlgorithm.A128Kw) }
        CoseKey.of(pair.publicKey, algorithm = CoseAlgorithm.EcdhEsA128Kw).algorithm shouldBe CoseAlgorithm.EcdhEsA128Kw
    }
})
