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

package com.davils.krypt.jose

import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.jose.fixture.crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

private const val NAME = "name"
private const val KEY_ID = "kid-1"
private val KEY_TYPE: KeyType = KeyType.Ed25519

class ValuesTest : FunSpec({
    test("texts refuse lone surrogates and noncharacters") {
        JsonValue.Text("😀").value shouldBe "😀"
        listOf("\uD800", "a\uDC00", "\uD800a", "﷐", "￾", "🿿").forEach { text ->
            shouldThrow<IllegalArgumentException> { JsonValue.Text(text) }
        }
        shouldThrow<IllegalArgumentException> { JsonValue.Object.of("\uD800" to JsonValue.Null) }
    }

    test("integers stay within what a double represents exactly") {
        JsonValue.Integer(-JsonValue.Integer.MAXIMUM).value shouldBe -JsonValue.Integer.MAXIMUM
        shouldThrow<IllegalArgumentException> { JsonValue.Integer(JsonValue.Integer.MAXIMUM + 1) }
        shouldThrow<IllegalArgumentException> { JsonValue.Integer(-JsonValue.Integer.MAXIMUM - 1) }
    }

    test("values compare, hash and show themselves") {
        JsonValue.Text("a") shouldBe JsonValue.Text("a")
        JsonValue.Text("a") shouldNotBe JsonValue.Text("b")
        JsonValue.Text("a") shouldNotBe JsonValue.Null
        JsonValue.Text("a").hashCode() shouldBe JsonValue.Text("a").hashCode()
        JsonValue.Text("a\nb").toString() shouldNotContain "\n"
        JsonValue.Integer(1) shouldBe JsonValue.Integer(1)
        JsonValue.Integer(1) shouldNotBe JsonValue.Integer(2)
        JsonValue.Integer(1) shouldNotBe JsonValue.Text("1")
        JsonValue.Integer(1).hashCode() shouldBe JsonValue.Integer(1).hashCode()
        JsonValue.Integer(1).toString() shouldBe "1"
        JsonValue.Bool(true) shouldBe JsonValue.Bool(true)
        JsonValue.Bool(true) shouldNotBe JsonValue.Bool(false)
        JsonValue.Bool(true) shouldNotBe JsonValue.Null
        JsonValue.Bool(true).hashCode() shouldBe JsonValue.Bool(true).hashCode()
        JsonValue.Bool(false).toString() shouldBe "false"
        JsonValue.Null.toString() shouldBe "null"
        val array = JsonValue.Array(listOf(JsonValue.Null))
        array shouldBe JsonValue.Array(listOf(JsonValue.Null))
        array shouldNotBe JsonValue.Array(emptyList())
        array shouldNotBe JsonValue.Null
        array.hashCode() shouldBe JsonValue.Array(listOf(JsonValue.Null)).hashCode()
        array.toString() shouldContain "1"
    }

    test("objects keep their order, look members up and compare regardless of order") {
        val first = JsonValue.Object.of("a" to JsonValue.Integer(1), "b" to JsonValue.Integer(2))
        val second = JsonValue.Object.of("b" to JsonValue.Integer(2), "a" to JsonValue.Integer(1))
        first.names shouldBe listOf("a", "b")
        first["a"] shouldBe JsonValue.Integer(1)
        first["c"] shouldBe null
        ("a" in first) shouldBe true
        ("c" in first) shouldBe false
        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
        first shouldNotBe JsonValue.Object.of("a" to JsonValue.Integer(1))
        first shouldNotBe JsonValue.Object.of("a" to JsonValue.Integer(1), "b" to JsonValue.Integer(value = 3))
        first shouldNotBe JsonValue.Null
        first.encode() shouldBe """{"a":1,"b":2}"""
        first.toString() shouldBe "Object(a, b)"
        shouldThrow<IllegalArgumentException> { JsonValue.Object.of("a" to JsonValue.Null, "a" to JsonValue.Null) }
    }

    test("limits check their ceilings and compare") {
        JoseLimits() shouldBe JoseLimits.Default
        JoseLimits().hashCode() shouldBe JoseLimits.Default.hashCode()
        JoseLimits(maximumKeys = 1) shouldNotBe JoseLimits.Default
        JoseLimits.Default shouldNotBe NAME
        JoseLimits.Default.toString() shouldContain "maximumIterations"
        listOf<() -> JoseLimits>(
            { JoseLimits(maximumBytes = 0) },
            { JoseLimits(maximumBytes = JoseLimits.HARD_MAXIMUM_BYTES + 1) },
            { JoseLimits(maximumDepth = 0) },
            { JoseLimits(maximumDepth = JoseLimits.HARD_MAXIMUM_DEPTH + 1) },
            { JoseLimits(maximumMembers = 0) },
            { JoseLimits(maximumMembers = JoseLimits.HARD_MAXIMUM_MEMBERS + 1) },
            { JoseLimits(maximumStringLength = 0) },
            { JoseLimits(maximumStringLength = JoseLimits.HARD_MAXIMUM_STRING_LENGTH + 1) },
            { JoseLimits(maximumRecipients = 0) },
            { JoseLimits(maximumRecipients = JoseLimits.HARD_MAXIMUM_RECIPIENTS + 1) },
            { JoseLimits(maximumCertificates = 0) },
            { JoseLimits(maximumCertificates = JoseLimits.HARD_MAXIMUM_CERTIFICATES + 1) },
            { JoseLimits(maximumKeys = 0) },
            { JoseLimits(maximumKeys = JoseLimits.HARD_MAXIMUM_KEYS + 1) },
            { JoseLimits(maximumIterations = 0) },
            { JoseLimits(maximumIterations = JoseLimits.HARD_MAXIMUM_ITERATIONS + 1) },
        ).forEach { create -> shouldThrow<IllegalArgumentException> { create() } }
        val outcome1 = JoseLimits(
            maximumBytes = JoseLimits.HARD_MAXIMUM_BYTES,
            maximumDepth = JoseLimits.HARD_MAXIMUM_DEPTH,
            maximumMembers = JoseLimits.HARD_MAXIMUM_MEMBERS,
            maximumStringLength = JoseLimits.HARD_MAXIMUM_STRING_LENGTH,
            maximumRecipients = JoseLimits.HARD_MAXIMUM_RECIPIENTS,
            maximumCertificates = JoseLimits.HARD_MAXIMUM_CERTIFICATES,
            maximumKeys = JoseLimits.HARD_MAXIMUM_KEYS,
            maximumIterations = JoseLimits.HARD_MAXIMUM_ITERATIONS,
        )
        outcome1.maximumBytes shouldBe JoseLimits.HARD_MAXIMUM_BYTES
    }

    test("keys compare by key and id and never show secrets") {
        val secret = crypto.keys.generateSecret()
        val pair = crypto.keys.generate(KEY_TYPE)
        val password = SecretText.of("password")
        val keys = listOf(
            JoseKey.Secret(secret, KEY_ID),
            JoseKey.Public(pair.publicKey, KEY_ID),
            JoseKey.Private(pair.privateKey, KEY_ID),
            JoseKey.Password(password, KEY_ID),
        )
        val same = listOf(
            JoseKey.Secret(secret, KEY_ID),
            JoseKey.Public(pair.publicKey, KEY_ID),
            JoseKey.Private(pair.privateKey, KEY_ID),
            JoseKey.Password(password, KEY_ID),
        )
        val other = listOf(
            JoseKey.Secret(secret),
            JoseKey.Public(pair.publicKey),
            JoseKey.Private(pair.privateKey),
            JoseKey.Password(password),
        )
        keys.indices.forEach { index ->
            keys[index] shouldBe same[index]
            keys[index].hashCode() shouldBe same[index].hashCode()
            keys[index] shouldNotBe other[index]
            keys[index] shouldNotBe NAME
            keys[index].toString() shouldContain KEY_ID
            other[index].toString() shouldContain "none"
        }
        JoseKey.Secret(secret) shouldNotBe JoseKey.Secret(crypto.keys.generateSecret())
        JoseKey.Public(pair.publicKey) shouldNotBe JoseKey.Public(crypto.keys.generate(KEY_TYPE).publicKey)
        JoseKey.Private(pair.privateKey) shouldNotBe JoseKey.Private(crypto.keys.generate(KEY_TYPE).privateKey)
        JoseKey.Password(password) shouldNotBe JoseKey.Password(SecretText.of("other"))
        keys.last().toString() shouldNotContain "password"
    }

    test("headers read their well-known members") {
        val header = JoseHeader(
            JsonValue.Object.of(
                "alg" to JsonValue.Text("HS256"),
                "enc" to JsonValue.Text("A128GCM"),
                "kid" to JsonValue.Text(KEY_ID),
                "typ" to JsonValue.Text("JWT"),
                "cty" to JsonValue.Text("text/plain"),
                "crit" to JsonValue.Array(listOf(JsonValue.Text("b64"))),
            ),
        )
        header.algorithm shouldBe "HS256"
        header.encryption shouldBe "A128GCM"
        header.keyId shouldBe KEY_ID
        header.type shouldBe "JWT"
        header.contentType shouldBe "text/plain"
        header.critical shouldBe listOf("b64")
        header["kid"] shouldBe JsonValue.Text(KEY_ID)
        val empty = JoseHeader(JsonValue.Object.Empty)
        empty.algorithm shouldBe null
        empty.critical shouldBe emptyList()
        header shouldBe JoseHeader(header.members)
        header.hashCode() shouldBe JoseHeader(header.members).hashCode()
        header shouldNotBe empty
        header shouldNotBe NAME
        header.toString() shouldContain "kid"
        JoseHeader(JsonValue.Object.of("crit" to JsonValue.Integer(1))).critical shouldBe emptyList()
        JoseHeader(JsonValue.Object.of("alg" to JsonValue.Integer(1))).algorithm shouldBe null
    }
})
