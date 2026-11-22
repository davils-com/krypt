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

package com.davils.krypt.jose.jws

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.base64
import com.davils.krypt.jose.fixture.crypto
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.x509.path.PathValidator
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private const val KID = "named"
private val engine = Jws(crypto)
private val body = utf8("edge")
private val hs256 = setOf(JwsAlgorithm.HS256)

private fun secret(keyId: String? = null): JoseKey = JoseKey.Secret(key = crypto.keys.generateSecret(), keyId = keyId)

class JwsEdgeTest : FunSpec({
    test("tries every fitting key in order and stops at the first that verifies") {
        val right = secret(KID)
        val compact = engine.sign(body, JwsSigner(right, JwsAlgorithm.HS256))
        engine.verify(text = compact, keys = listOf(secret(), right), algorithms = hs256).value().key shouldBe right
        engine.verify(text = compact, keys = listOf(right, secret()), algorithms = hs256).value().key shouldBe right
        val unnamed = engine.sign(body, JwsSigner(secret(), JwsAlgorithm.HS256))
        engine.verify(text = unnamed, keys = listOf(secret(KID)), algorithms = hs256).failure() shouldBe
            JoseFailure.BadSignature
    }

    test("keeps a key id the header already names") {
        val header = JsonValue.Object.of("kid" to JsonValue.Text(KID))
        val compact = engine.sign(body, JwsSigner(secret("other"), JwsAlgorithm.HS256, header))
        val decoded = engine.decode(compact).value()
        val signature = decoded.signatures.single()
        signature.header.keyId shouldBe KID
    }

    test("compares messages and signatures by every part") {
        val key = secret()
        val signer = JwsSigner(key, JwsAlgorithm.HS256, unprotectedHeader = JsonValue.Object.of("x" to JsonValue.Null))
        val flattened = engine.signJson(body, listOf(signer), isFlattened = true)
        val withOtherHeader = flattened.replace(oldValue = """"x":null""", newValue = """"y":null""")
        val first = engine.decode(flattened).value()
        val second = engine.decode(withOtherHeader).value()
        first.signatures.single() shouldNotBe second.signatures.single()
        val compact = engine.sign(body, JwsSigner(key, JwsAlgorithm.HS256))
        val parts = compact.split('.')
        val otherPayload = engine.decode("${parts[0]}.${base64("other")}.${parts[2]}").value()
        val decoded = engine.decode(compact).value()
        decoded shouldNotBe otherPayload
        val json = """{"payload":"${parts[1]}","protected":"${parts[0]}","signature":"${parts[2]}"}"""
        decoded shouldNotBe engine.decode(json).value()
    }

    test("verifies a chain with the default parameters and refuses a broken certificate") {
        val pair = crypto.keys.generate(KeyType.P256)
        val validator = PathValidator(crypto, emptyList())
        val signer = JwsSigner(
            key = JoseKey.Private(pair.privateKey),
            algorithm = JwsAlgorithm.ES256,
            header = JsonValue.Object.of("x5c" to JsonValue.Array(listOf(JsonValue.Text("!!")))),
        )
        val message = engine.decode(engine.sign(body, signer)).value()
        engine.verifyWithChain(message, validator, setOf(JwsAlgorithm.ES256)).failure() shouldBe JoseFailure.Malformed
    }
})
