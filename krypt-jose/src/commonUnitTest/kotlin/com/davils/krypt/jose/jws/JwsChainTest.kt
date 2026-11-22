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
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.fixture.NOW
import com.davils.krypt.jose.fixture.crypto
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.path.PathValidator
import com.davils.krypt.x509.path.TrustAnchor
import com.davils.krypt.x509.path.ValidationParameters
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days

private val certificates = Certificates(crypto)
private val parameters = ValidationParameters(isRevocationRequired = false)
private val payload = utf8("signed with a certificate")

private suspend fun issued(name: String, pair: KeyPair, issuer: Certificate?, signer: KeyPair): Certificate =
    certificates.issue(crypto.signatures.signer(signer.privateKey)) {
        subject { commonName(name) }
        issuer?.let { found -> this.issuer = found.subject }
        publicKey = pair.publicKey
        notBefore = NOW - 1.days
        notAfter = NOW + 1.days
        extensions {
            basicConstraints(isCa = issuer == null)
            keyUsage(setOf(KeyUsage.DigitalSignature, KeyUsage.KeyCertSign))
        }
    }

private suspend fun Jws.chained(signer: JwsSigner, validator: PathValidator): JoseFailure? {
    val message = decode(sign(payload, signer)).value()
    val outcome1 = verifyWithChain(
        message = message,
        validator = validator,
        algorithms = setOf(JwsAlgorithm.ES256),
        parameters = parameters,
    )
    return outcome1.failure()
}

private fun chainOf(certificates: List<Certificate>): JsonValue = JsonValue.Array(
    certificates.map { certificate -> JsonValue.Text(Base64.encode(certificate.encoded)) },
)

class JwsChainTest : FunSpec({
    test("verifies a signature with the key of a validated x5c chain") {
        val rootKeys = crypto.keys.generate(KeyType.P256)
        val root = issued(name = "Root", pair = rootKeys, issuer = null, signer = rootKeys)
        val leafKeys = crypto.keys.generate(KeyType.P256)
        val leaf = issued(name = "Leaf", pair = leafKeys, issuer = root, signer = rootKeys)
        val jws = Jws(crypto)
        val validator = PathValidator(crypto, listOf(TrustAnchor.of(root)))
        val es256 = setOf(JwsAlgorithm.ES256)
        val signer = JwsSigner(
            key = JoseKey.Private(leafKeys.privateKey),
            algorithm = JwsAlgorithm.ES256,
            header = JsonValue.Object.of("x5c" to chainOf(listOf(leaf, root))),
        )
        val message = jws.decode(jws.sign(payload = payload, signer = signer)).value()
        val outcome2 = jws.verifyWithChain(
            message = message,
            validator = validator,
            algorithms = es256,
            parameters = parameters,
        )
        val verified = outcome2.value()
        verified.payload shouldBe payload
        verified.key shouldBe JoseKey.Public(leafKeys.publicKey)
        val otherKeys = crypto.keys.generate(KeyType.P256)
        val stranger = PathValidator(
            crypto,
            listOf(TrustAnchor.of(issued(name = "Other", pair = otherKeys, issuer = null, signer = otherKeys))),
        )
        val outcome3 = jws.verifyWithChain(
            message = message,
            validator = stranger,
            algorithms = es256,
            parameters = parameters,
        )
        outcome3.failure() shouldBe JoseFailure.UntrustedCertificate
        val plain = jws.decode(
            jws.sign(payload = payload, signer = JwsSigner(JoseKey.Private(leafKeys.privateKey), JwsAlgorithm.ES256)),
        )
        val outcome4 = jws.verifyWithChain(
            message = plain.value(),
            validator = validator,
            algorithms = es256,
            parameters = parameters,
        )
        outcome4.failure() shouldBe
            JoseFailure.UntrustedCertificate
        val long = JwsSigner(
            key = JoseKey.Private(leafKeys.privateKey),
            algorithm = JwsAlgorithm.ES256,
            header = JsonValue.Object.of("x5c" to chainOf(List(JoseLimits.DEFAULT_MAXIMUM_CERTIFICATES + 1) { leaf })),
        )
        jws.chained(long, validator) shouldBe JoseFailure.LimitExceeded
        val undecodable = List(JoseLimits.DEFAULT_MAXIMUM_CERTIFICATES + 1) { JsonValue.Text("!") }
        val longGarbage = JwsSigner(
            key = JoseKey.Private(leafKeys.privateKey),
            algorithm = JwsAlgorithm.ES256,
            header = JsonValue.Object.of("x5c" to JsonValue.Array(undecodable)),
        )
        jws.chained(longGarbage, validator) shouldBe JoseFailure.LimitExceeded
        val broken = JwsSigner(
            key = JoseKey.Private(leafKeys.privateKey),
            algorithm = JwsAlgorithm.ES256,
            header = JsonValue.Object.of("x5c" to JsonValue.Array(listOf(JsonValue.Text("AAAA")))),
        )
        jws.chained(broken, validator) shouldBe JoseFailure.Malformed
        val wrongKey = JwsSigner(
            key = JoseKey.Private(otherKeys.privateKey),
            algorithm = JwsAlgorithm.ES256,
            header = JsonValue.Object.of("x5c" to chainOf(listOf(leaf, root))),
        )
        jws.chained(wrongKey, validator) shouldBe JoseFailure.BadSignature
    }
})
