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

package com.davils.krypt.jose.jwk

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.Rfc7520
import com.davils.krypt.jose.fixture.Vectors
import com.davils.krypt.jose.fixture.base64
import com.davils.krypt.jose.fixture.compatible
import com.davils.krypt.jose.fixture.compatibleKeys
import com.davils.krypt.jose.fixture.crypto
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.jwkOf
import com.davils.krypt.jose.fixture.keys
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.jose.internal.JsonReader
import com.davils.krypt.jose.internal.KeyDer
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import io.kotest.matchers.types.shouldBeInstanceOf

private const val X = "x"
private const val KTY = "kty"
private const val CRV = "crv"
private const val KEY_ID = "kid-7"

private const val COORDINATE_BYTES = 32
private const val SIGN = "sign"
private const val KEY_OPS = "key_ops"
private const val URN = "urn:ietf:params:oauth:jwk-thumbprint:"

private val ecObject: JsonValue.Object = JsonValue.Object.of(
    KTY to JsonValue.Text("EC"),
    CRV to JsonValue.Text("P-256"),
    X to JsonValue.Text("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"),
    "y" to JsonValue.Text("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"),
)
private val ecMembers: List<Pair<String, JsonValue>> = ecObject.members

private fun ec(vararg changes: Pair<String, JsonValue?>): String = edited(base = ecMembers, changes = changes.toList())

private fun edited(base: List<Pair<String, JsonValue>>, changes: List<Pair<String, JsonValue?>>): String {
    val names = changes.map { (name, _) -> name }.toSet()
    val kept = base.filterNot { (name, _) -> name in names }
    val added = changes.mapNotNull { (name, value) -> value?.let { found -> name to found } }
    return JsonValue.Object(kept + added).encode()
}

private fun text(value: String): JsonValue = JsonValue.Text(value)

private fun texts(vararg values: String): JsonValue = JsonValue.Array(values.map { value -> JsonValue.Text(value) })

private fun failureOf(text: String): JoseFailure? = keys.decode(text).failure()

class JwkTest : FunSpec({
    test("RFC 7517 A.1 reads a set of an EC and an RSA public key") {
        val set = keys.decodeSet(Vectors.RFC7517_KEY_SET).value()
        set.keys shouldHaveSize 2
        val ecKey = set.keys[0]
        ecKey.type shouldBe JwkType.Ec
        ecKey.curve shouldBe JwkCurve.P256
        ecKey.use shouldBe KeyUse.Encryption
        ecKey.keyId shouldBe "1"
        ecKey.isPrivate shouldBe false
        ecKey.parameter(X)?.size shouldBe COORDINATE_BYTES
        ecKey.parameter("n") shouldBe null
        val rsaKey = set.find("2011-04-29").single()
        rsaKey.type shouldBe JwkType.Rsa
        rsaKey.algorithm shouldBe "RS256"
        rsaKey.curve shouldBe null
        set.find("none") shouldBe emptyList()
        keys.decodeSet(set.encode()).value() shouldBe set
    }

    test("RFC 7638 and RFC 8037 compute thumbprints and RFC 9278 their URIs") {
        val rsaKey = keys.decodeSet(Vectors.RFC7517_KEY_SET).value().keys[1]
        base64(keys.thumbprint(rsaKey)) shouldBe Vectors.RFC7638_THUMBPRINT
        val ed25519 = jwkOf(Vectors.RFC8037_PRIVATE)
        base64(keys.thumbprint(ed25519)) shouldBe Vectors.RFC8037_THUMBPRINT
        keys.thumbprintUri(ed25519) shouldBe "${URN}sha-256:${Vectors.RFC8037_THUMBPRINT}"
        keys.thumbprintUri(ed25519, DigestAlgorithm.Sha384) shouldStartWith "${URN}sha-384:"
        keys.thumbprintUri(ed25519, DigestAlgorithm.Sha512) shouldStartWith "${URN}sha-512:"
        shouldThrow<IllegalArgumentException> { keys.thumbprintUri(ed25519, DigestAlgorithm.Sha3256) }
        val secret = jwkOf(Rfc7520.HMAC_KEY)
        keys.thumbprint(secret).size shouldBe COORDINATE_BYTES
    }

    test("RFC 7517 B reads a key with its certificate and refuses one whose certificate holds another key") {
        val jwk = compatibleKeys.decode(Vectors.RFC7517_X5C_KEY).value()
        jwk.certificates shouldHaveSize 1
        compatibleKeys.decode(jwk.encode()).value() shouldBe jwk
        val other = jwkOf(Rfc7520.RSA_PRIVATE).toPublic()
        val parsed = JsonValue.Object(
            objectOf(jwk.encode()).members.map { (name, value) ->
                name to (other?.parameter(name)?.let { bytes -> text(base64(bytes)) } ?: value)
            },
        )
        compatibleKeys.decode(parsed.encode()).failure() shouldBe JoseFailure.InvalidKey
    }

    test("converts every key type to a JWK and back") {
        val outcome1 = listOf(
            KeyType.P256,
            KeyType.P384,
            KeyType.P521,
            KeyType.Ed25519,
            KeyType.Ed448,
            KeyType.X25519,
            KeyType.X448,
        )
        outcome1.forEach { type -> roundTrip(engine = crypto, jwks = keys, type = type) }
        roundTrip(engine = compatible, jwks = compatibleKeys, type = KeyType.Rsa2048)
        val secret = crypto.keys.generateSecret()
        val jwk = keys.of(secret, keyId = KEY_ID, algorithm = "HS256")
        jwk.isPrivate shouldBe true
        jwk.toPublic() shouldBe null
        keys.secretKey(keys.decode(jwk.encode()).value()).value() shouldBe secret
        keys.key(jwk).value() shouldBe JoseKey.Secret(key = secret, keyId = KEY_ID, algorithm = "HS256")
    }

    test("refuses a private key whose parts do not belong together") {
        val first = keys.of(crypto.keys.generate(KeyType.P256).privateKey)
        val second = keys.of(crypto.keys.generate(KeyType.P256).privateKey)
        val mixed = JsonValue.Object(
            objectOf(first.encode()).members.map { (name, value) ->
                name to (value.takeUnless { name == "d" } ?: memberOf(text = second.encode(), name = "d"))
            },
        )
        keys.privateKey(keys.decode(mixed.encode()).value()).failure() shouldBe JoseFailure.InvalidKey
    }

    test("refuses conversions that do not fit the key") {
        val secret = jwkOf(Rfc7520.HMAC_KEY)
        val public = checkNotNull(jwkOf(Vectors.RFC7515_EC_KEY).toPublic())
        keys.publicKey(secret).failure() shouldBe JoseFailure.InvalidKey
        keys.privateKey(secret).failure() shouldBe JoseFailure.InvalidKey
        keys.privateKey(public).failure() shouldBe JoseFailure.InvalidKey
        keys.secretKey(public).failure() shouldBe JoseFailure.InvalidKey
        keys.secretKey(jwkOf("""{"kty":"oct","k":"AAAAAAAAAAA"}""")).failure() shouldBe JoseFailure.InvalidKey
        val converted = keys.key(public).value()
        converted.shouldBeInstanceOf<JoseKey.Public>()
        val cnsa = JsonWebKeys(Crypto(environment { policy = CryptoPolicy.Cnsa2 }))
        cnsa.publicKey(public).failure() shouldBe JoseFailure.InvalidKey
        cnsa.key(jwkOf(Vectors.RFC7515_EC_KEY)).failure() shouldBe JoseFailure.InvalidKey
        val x25519 = KeyDer.pkcs8(keys.of(crypto.keys.generate(KeyType.X25519).privateKey))
        val unpaired = checkNotNull(crypto.keys.decodePrivate(x25519).getOrNull())
        shouldThrow<IllegalArgumentException> { keys.of(unpaired) }
    }

    test("refuses malformed and unsupported keys") {
        val outcome2 = listOf(
            ec(KTY to null),
            ec(KTY to JsonValue.Integer(1)),
            ec("y" to null),
            ec(X to text("AAAA")),
            ec(X to text("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU=")),
            ec(X to text("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEV")),
            ec("n" to text("AQAB")),
            ec(CRV to null),
            ec(CRV to text("Ed25519")),
            ec("d" to text("AAAA")),
            ec(KEY_OPS to texts(SIGN, SIGN)),
            ec(KEY_OPS to texts(SIGN), "use" to text("enc")),
            ec(KEY_OPS to text(SIGN)),
            ec("x5c" to texts()),
            ec("x5c" to texts("!!")),
            ec("x5c" to texts("AAAA")),
            ec("x5c" to JsonValue.Integer(1)),
            ec("x5u" to JsonValue.Integer(1)),
            ec("kid" to JsonValue.Integer(1)),
            """{"kty":"RSA","n":"AKs","e":"AQAB"}""",
            """{"kty":"RSA","n":"qw","e":"AQAB","d":"AQ"}""",
            """{"kty":"RSA","n":"qw","e":"AQAB","crv":"P-256"}""",
            """{"kty":"RSA","n":"","e":"AQAB"}""",
            """{"kty":"oct"}""",
            """{"kty":"oct","k":""}""",
            """{"kty":"oct","k":"AAAAAAAAAAAAAAAAAAAAAA","x5c":["AAAA"]}""",
            """{"kty":"OKP","crv":"P-256","x":"AAAA"}""",
            "[]",
            """{"kty":"oct","k":"AAAA"""",
            "\uD800",
        )
        outcome2.forEach { text -> failureOf(text) shouldBe JoseFailure.Malformed }
        val outcome3 = listOf(
            ec(KTY to text("XYZ")),
            ec(CRV to text("P-192")),
            ec("use" to text("wrap")),
            ec(KEY_OPS to texts("print")),
            """{"kty":"RSA","n":"qw","e":"AQAB","oth":[]}""",
        )
        outcome3.forEach { text -> failureOf(text) shouldBe JoseFailure.UnsupportedAlgorithm }
        val chain = List(JoseLimits.DEFAULT_MAXIMUM_CERTIFICATES + 1) { text("AAAA") }
        failureOf(ec("x5c" to JsonValue.Array(chain))) shouldBe JoseFailure.LimitExceeded
        val small = JsonWebKeys(crypto, JoseLimits(maximumBytes = 8))
        small.decode(ec()).failure() shouldBe JoseFailure.LimitExceeded
    }

    test("keeps metadata and members it does not interpret") {
        val text = ec(
            "use" to text("sig"),
            KEY_OPS to texts("verify"),
            "alg" to text("ES256"),
            "kid" to text(KEY_ID),
            "x5t#S256" to text("abc"),
            "custom" to JsonValue.Bool(true),
        )
        val jwk = keys.decode(text).value()
        jwk.operations shouldBe listOf(KeyOperation.Verify)
        jwk.extra.names shouldBe listOf("x5t#S256", "custom")
        keys.decode(jwk.encode()).value() shouldBe jwk
        jwk.toString() shouldContain KEY_ID
        val again = keys.decode(text).value()
        jwk.hashCode() shouldBe again.hashCode()
        jwk shouldNotBe keys.decode(ec()).value()
        jwk shouldNotBe KEY_ID
    }

    test("hides and wipes private parameters") {
        val jwk = keys.of(crypto.keys.generate(KeyType.P256).privateKey, keyId = KEY_ID, use = KeyUse.Signature)
        val encoded = jwk.encode()
        val d = memberOf(text = encoded, name = "d").toString()
        jwk.toString() shouldNotContain d.trim('"')
        jwk shouldBe keys.decode(encoded).value()
        jwk shouldNotBe jwk.toPublic()
        jwk.isDestroyed shouldBe false
        jwk.destroy()
        jwk.isDestroyed shouldBe true
        shouldThrow<IllegalStateException> { jwk.encode() }
        shouldThrow<IllegalStateException> { JwkSet(listOf(jwk)).encode() }
        keys.toString() shouldContain "JsonWebKeys"
    }

    test("reads a set and leaves out the keys it cannot read") {
        val text = """{"keys":[${ec()},{"kty":"XYZ"},{"kty":"EC"},${Rfc7520.HMAC_KEY}],"extra":1}"""
        val set = keys.decodeSet(text).value()
        set.keys shouldHaveSize 2
        set.toPublic().keys shouldHaveSize 1
        set shouldBe JwkSet(set.keys)
        set.hashCode() shouldBe JwkSet(set.keys).hashCode()
        set shouldNotBe set.toPublic()
        set shouldNotBe KEY_ID
        set.toString() shouldContain "JwkSet"
        keys.decodeSet("{}").failure() shouldBe JoseFailure.Malformed
        keys.decodeSet("""{"keys":{}}""").failure() shouldBe JoseFailure.Malformed
        keys.decodeSet("""{"keys":[1]}""").failure() shouldBe JoseFailure.Malformed
        keys.decodeSet("[]").failure() shouldBe JoseFailure.Malformed
        val tooMany = (1..JoseLimits.DEFAULT_MAXIMUM_KEYS + 1).joinToString(prefix = """{"keys":[""", postfix = "]}") {
            "{}"
        }
        val wide = JsonWebKeys(crypto, JoseLimits(maximumMembers = 128))
        wide.decodeSet(tooMany).failure() shouldBe
            JoseFailure.LimitExceeded
    }

    test("names every type, curve, use and operation") {
        JwkType.entries.forEach { type -> JwkType.of(type.typeName) shouldBe type }
        JwkType.of("ec") shouldBe null
        JwkCurve.entries.forEach { curve -> JwkCurve.of(curve.curveName) shouldBe curve }
        JwkCurve.of("p-256") shouldBe null
        JwkCurve.of(family = KeyFamily.Rsa, curve = null) shouldBe null
        KeyUse.entries.forEach { use -> KeyUse.of(use.useName) shouldBe use }
        KeyOperation.entries.forEach { operation -> KeyOperation.of(operation.operationName) shouldBe operation }
    }
})

private fun objectOf(text: String): JsonValue.Object =
    JsonReader.readObject(bytes = text.encodeToByteArray(), limits = JoseLimits.Default).value()

private suspend fun roundTrip(engine: Crypto, jwks: JsonWebKeys, type: KeyType) {
    val pair = engine.keys.generate(type)
    val publicJwk = jwks.of(key = pair.publicKey, keyId = KEY_ID, use = KeyUse.Signature, algorithm = "x")
    val decodedPublic = jwks.decode(publicJwk.encode()).value()
    decodedPublic shouldBe publicJwk
    jwks.publicKey(decodedPublic).value() shouldBe pair.publicKey
    val privateJwk = jwks.of(key = pair.privateKey, keyId = KEY_ID)
    privateJwk.isPrivate shouldBe true
    privateJwk.toPublic()?.isPrivate shouldBe false
    val decodedPrivate = jwks.decode(privateJwk.encode()).value()
    val privateKey = jwks.privateKey(decodedPrivate).value()
    privateKey.publicKey shouldBe pair.publicKey
    val restored = jwks.of(key = privateKey)
    restored.encode() shouldBe jwks.of(key = pair.privateKey).encode()
    val converted = jwks.key(decodedPrivate).value()
    converted.shouldBeInstanceOf<JoseKey.Private>()
    jwks.thumbprint(decodedPublic) shouldBe jwks.thumbprint(decodedPrivate)
}

private fun memberOf(text: String, name: String): JsonValue = checkNotNull(objectOf(text)[name])
