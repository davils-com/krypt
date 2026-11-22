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
import com.davils.krypt.jose.fixture.failure
import com.davils.krypt.jose.fixture.keys
import com.davils.krypt.jose.fixture.utf8
import com.davils.krypt.jose.fixture.value
import com.davils.krypt.jose.jwe.Jwe
import com.davils.krypt.jose.jwe.JweAlgorithm
import com.davils.krypt.jose.jwe.JweEncryption
import com.davils.krypt.jose.jwe.JweRecipient
import com.davils.krypt.jose.jwk.KeyOperation
import com.davils.krypt.jose.jwk.KeyUse
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsSigner
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val HS256: String = "HS256"
private const val ES256: String = "ES256"

private val jws: Jws = Jws(crypto)

private val jwe: Jwe = Jwe(crypto)

private val payload: ByteString = utf8("payload")

private val hmac: Set<JwsAlgorithm> = setOf(JwsAlgorithm.HS256)

private suspend fun verified(token: String, key: JoseKey): JoseFailure? =
    jws.verify(text = token, keys = listOf(key), algorithms = hmac).failure()

private suspend fun decrypted(token: String, key: JoseKey): JoseFailure? {
    val outcome = jwe.decrypt(
        text = token,
        keys = listOf(key),
        algorithms = setOf(JweAlgorithm.Dir),
        encryptions = setOf(JweEncryption.A256GCM),
    )
    return outcome.failure()
}

class JoseKeyUsageTest : FunSpec({
    test("a JWK keeps its use, key_ops and alg on its key") {
        val pair = crypto.keys.generate(KeyType.P256)
        val signing = keys.key(keys.of(key = pair.publicKey, use = KeyUse.Signature, algorithm = ES256)).value()
        signing.use shouldBe KeyUse.Signature
        signing.algorithm shouldBe ES256
        signing.operations shouldBe emptySet()
        val secret = keys.key(keys.of(key = crypto.keys.generateSecret(), algorithm = HS256)).value()
        secret.algorithm shouldBe HS256
        val private = keys.key(keys.of(key = pair.privateKey, use = KeyUse.Encryption)).value()
        private.use shouldBe KeyUse.Encryption
        JoseKey.Password(SecretText.of("x")).use shouldBe null
    }

    test("a signature is verified and made only with a key whose use, key_ops and alg fit") {
        val secret = crypto.keys.generateSecret()
        val token = jws.sign(payload = payload, signer = JwsSigner(JoseKey.Secret(secret), JwsAlgorithm.HS256))
        listOf(
            JoseKey.Secret(key = secret),
            JoseKey.Secret(key = secret, use = KeyUse.Signature),
            JoseKey.Secret(key = secret, operations = setOf(KeyOperation.Verify)),
            JoseKey.Secret(key = secret, algorithm = HS256),
        ).forEach { key -> verified(token, key) shouldBe null }
        listOf(
            JoseKey.Secret(key = secret, use = KeyUse.Encryption),
            JoseKey.Secret(key = secret, operations = setOf(KeyOperation.Sign)),
            JoseKey.Secret(key = secret, algorithm = "HS512"),
        ).forEach { key ->
            verified(token, key) shouldBe JoseFailure.KeyNotFound
        }
        val verifyOnly = JoseKey.Secret(key = secret, operations = setOf(KeyOperation.Verify))
        shouldThrow<IllegalArgumentException> {
            jws.sign(payload = payload, signer = JwsSigner(verifyOnly, JwsAlgorithm.HS256))
        }
    }

    test("a JWE is encrypted and decrypted only with a key whose use, key_ops and alg fit") {
        val secret = crypto.keys.generateSecret()
        val sealed = jwe.encrypt(payload, JweRecipient(JoseKey.Secret(secret), JweAlgorithm.Dir), JweEncryption.A256GCM)
        listOf(
            JoseKey.Secret(key = secret, use = KeyUse.Encryption),
            JoseKey.Secret(key = secret, operations = setOf(KeyOperation.Decrypt)),
            JoseKey.Secret(key = secret, algorithm = "dir"),
            JoseKey.Secret(key = secret, algorithm = "A256GCM"),
        ).forEach { key -> decrypted(sealed, key) shouldBe null }
        listOf(
            JoseKey.Secret(key = secret, use = KeyUse.Signature),
            JoseKey.Secret(key = secret, operations = setOf(KeyOperation.Encrypt)),
            JoseKey.Secret(key = secret, algorithm = HS256),
        ).forEach { key -> decrypted(sealed, key) shouldBe JoseFailure.KeyNotFound }
        val signingKey = JoseKey.Secret(key = secret, use = KeyUse.Signature)
        shouldThrow<IllegalArgumentException> {
            jwe.encrypt(payload, JweRecipient(signingKey, JweAlgorithm.Dir), JweEncryption.A256GCM)
        }
    }

    test("the limits of use are part of the value of a key") {
        val secret = crypto.keys.generateSecret()
        val pair = crypto.keys.generate(KeyType.P256)
        val limited = JoseKey.Secret(
            key = secret,
            use = KeyUse.Signature,
            operations = setOf(KeyOperation.Sign),
            algorithm = HS256,
        )
        limited shouldBe JoseKey.Secret(
            key = secret,
            use = KeyUse.Signature,
            operations = setOf(KeyOperation.Sign),
            algorithm = HS256,
        )
        limited shouldNotBe JoseKey.Secret(secret)
        limited.hashCode() shouldNotBe JoseKey.Secret(secret).hashCode()
        limited.toString() shouldContain "use=sig, key_ops=[sign], alg=HS256"
        JoseKey.Public(key = pair.publicKey, use = KeyUse.Signature) shouldNotBe JoseKey.Public(pair.publicKey)
        JoseKey.Public(key = pair.publicKey, algorithm = ES256).toString() shouldContain "alg=ES256"
        JoseKey.Private(key = pair.privateKey, use = KeyUse.Encryption) shouldNotBe JoseKey.Private(pair.privateKey)
        JoseKey.Private(key = pair.privateKey, use = KeyUse.Encryption).toString() shouldContain "use=enc"
    }
})
