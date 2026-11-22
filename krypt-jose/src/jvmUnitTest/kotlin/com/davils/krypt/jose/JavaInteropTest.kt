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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsSigner
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

private const val RSA_BITS = 2_048
private const val COORDINATE_BYTES = 32
private val crypto = Crypto(environment { policy = CryptoPolicy.Compatible })
private val keys = JsonWebKeys(crypto)

private fun unsigned(bytes: ByteString): BigInteger = BigInteger(1, bytes.toByteArray())

private fun padded(value: BigInteger): ByteArray {
    val all = value.toByteArray()
    val bytes = all.takeLast(COORDINATE_BYTES).toByteArray()
    return ByteArray(COORDINATE_BYTES - bytes.size) + bytes
}

class JavaInteropTest : FunSpec({
    test("writes the RSA parameters java.security sees") {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(RSA_BITS)
        val pair = generator.generateKeyPair()
        val publicKey = checkNotNull(crypto.keys.decodePublic(ByteString(pair.public.encoded)).getOrNull())
        val jwk = keys.of(publicKey)
        val java = pair.public as RSAPublicKey
        unsigned(checkNotNull(jwk.parameter("n"))) shouldBe java.modulus
        unsigned(checkNotNull(jwk.parameter("e"))) shouldBe java.publicExponent
    }

    test("writes the EC point java.security sees and signs what it verifies") {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val pair = generator.generateKeyPair()
        val publicKey = checkNotNull(crypto.keys.decodePublic(ByteString(pair.public.encoded)).getOrNull())
        val jwk = keys.of(publicKey)
        val point = (pair.public as ECPublicKey).w
        unsigned(checkNotNull(jwk.parameter("x"))) shouldBe point.affineX
        unsigned(checkNotNull(jwk.parameter("y"))) shouldBe point.affineY
        val generated = crypto.keys.generate(KeyType.P256)
        val compact = Jws(crypto).sign(
            payload = "interop".encodeToByteString(),
            signer = JwsSigner(JoseKey.Private(generated.privateKey), JwsAlgorithm.ES256),
        )
        val parts = compact.split('.')
        val raw = Base64.getUrlDecoder().decode(parts[2])
        val r = BigInteger(1, raw.copyOfRange(fromIndex = 0, toIndex = COORDINATE_BYTES))
        val s = BigInteger(1, raw.copyOfRange(fromIndex = COORDINATE_BYTES, toIndex = raw.size))
        val verifier = Signature.getInstance("SHA256withECDSAinP1363Format")
        val javaKey = KeyFactory.getInstance("EC").generatePublic(
            X509EncodedKeySpec(generated.publicKey.encoded.toByteArray()),
        )
        verifier.initVerify(javaKey)
        verifier.update("${parts[0]}.${parts[1]}".toByteArray())
        verifier.verify(padded(r) + padded(s)) shouldBe true
    }

    test("refuses keys JOSE has no type for") {
        val mlDsa = crypto.keys.generate(KeyType.MlDsa44)
        shouldThrow<IllegalArgumentException> { keys.of(mlDsa.publicKey) }
    }
})
