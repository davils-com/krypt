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

package com.davils.krypt.keystore.material

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.keystore.KeystoreLimits
import com.davils.krypt.keystore.fixture.ITERATIONS
import com.davils.krypt.keystore.fixture.MemoryMaterial
import com.davils.krypt.keystore.fixture.certificates
import com.davils.krypt.keystore.fixture.crypto
import com.davils.krypt.keystore.fixture.identity
import com.davils.krypt.keystore.fixture.password
import com.davils.krypt.keystore.pkcs12.KeyEntry
import com.davils.krypt.keystore.pkcs12.Pkcs12
import com.davils.krypt.keystore.pkcs12.Pkcs12Store
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.path.TrustAnchor
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private val STORE: MaterialRef = MaterialRef("server.p12")
private val CHAIN: MaterialRef = MaterialRef("server.crt")
private val KEY: MaterialRef = MaterialRef("server.key")
private val BUNDLE: MaterialRef = MaterialRef("bundle.pem")
private const val SERVER: String = "server"
private const val SECRET: String = "secret"
private const val WRONG: String = "wrong"
private const val FIRST: String = "first"
private const val SECOND: String = "second"
private val TRUNCATED: ByteString = ByteString(0x30, 0)
private const val TOO_LONG: Int = 4_097
private val TWO_BYTES: ByteString = ByteString(1, 2)
private val FIVE_BYTES: ByteString = ByteString(1, 2, 3, 4, 5)
private val BROKEN_KEY: String = pem("PRIVATE KEY")
private val BROKEN_CERTIFICATE: String = pem("CERTIFICATE")

private fun pem(label: String): String {
    val lines = listOf("-----BEGIN $label-----", "AAAA", "-----END $label-----")
    return lines.joinToString(separator = "\n", postfix = "\n")
}

private suspend fun MaterialLoader.failureOf(spec: IdentitySpec): MaterialFailure? = identity(spec).failureOrNull()

class MaterialTest : FunSpec({
    test("identities round trip through PKCS #12 and PEM") {
        val material = MemoryMaterial()
        val writer = MaterialWriter(crypto, material)
        val loader = MaterialLoader(crypto, material)
        val (server, root) = identity()
        writer.writePkcs12(ref = STORE, identity = server, password = password(), alias = SERVER)
        loader.identity(IdentitySpec.KeyStore(STORE, password())).getOrNull() shouldBe server
        loader.identity(IdentitySpec.KeyStore(STORE, password(), alias = SERVER)).getOrNull() shouldBe server
        loader.failureOf(IdentitySpec.KeyStore(STORE, password(), alias = "other")) shouldBe MaterialFailure.NoKey
        loader.failureOf(IdentitySpec.KeyStore(STORE, password(WRONG))) shouldBe MaterialFailure.WrongPassword
        writer.writePem(
            certificates = CHAIN,
            key = KEY,
            identity = server,
            password = password(),
            iterations = ITERATIONS,
        )
        material.secrets shouldBe setOf(STORE, KEY)
        val encrypted = IdentitySpec.PemBundle(certificates = CHAIN, key = KEY, password = password())
        loader.identity(encrypted).getOrNull() shouldBe server
        loader.failureOf(IdentitySpec.PemBundle(certificates = CHAIN, key = KEY)) shouldBe MaterialFailure.WrongPassword
        val wrong = IdentitySpec.PemBundle(certificates = CHAIN, key = KEY, password = password(WRONG))
        loader.failureOf(wrong) shouldBe MaterialFailure.WrongPassword
        writer.writePem(certificates = CHAIN, key = KEY, identity = server)
        val keyText = checkNotNull(material.stored[KEY]).toByteArray()
        val chainText = checkNotNull(material.stored[CHAIN]).toByteArray()
        material.stored[BUNDLE] = ByteString(keyText + chainText)
        loader.identity(IdentitySpec.PemBundle(BUNDLE)).getOrNull() shouldBe server
        loader.certificates(CHAIN).getOrNull() shouldBe server.chain
        loader.certificates(BUNDLE).getOrNull() shouldBe server.chain
        material.stored[CHAIN] = root.certificate.encoded
        loader.certificates(CHAIN).getOrNull() shouldBe listOf(root.certificate)
        loader.anchors(CHAIN).getOrNull() shouldBe listOf(TrustAnchor.of(root.certificate))
        shouldThrow<IllegalArgumentException> { writer.writePem(certificates = CHAIN, key = CHAIN, identity = server) }
    }

    test("key stores with several keys need an alias") {
        val material = MemoryMaterial()
        val loader = MaterialLoader(crypto, material)
        val (first, _) = identity(FIRST)
        val (second, _) = identity(SECOND)
        val store = Pkcs12Store(keys = listOf(KeyEntry(first, alias = FIRST), KeyEntry(second, alias = SECOND)))
        material.stored[STORE] = Pkcs12(crypto).encode(store, password(), iterations = ITERATIONS)
        loader.identity(IdentitySpec.KeyStore(STORE, password())).failureOrNull() shouldBe MaterialFailure.AmbiguousKey
        loader.identity(IdentitySpec.KeyStore(STORE, password(), alias = SECOND)).getOrNull() shouldBe second
        material.stored[STORE] = Pkcs12(crypto).encode(Pkcs12Store(), password(), iterations = ITERATIONS)
        loader.identity(IdentitySpec.KeyStore(STORE, password())).failureOrNull() shouldBe MaterialFailure.NoKey
    }

    test("PEM bundles that do not form an identity are refused") {
        val material = MemoryMaterial()
        val loader = MaterialLoader(crypto, material)
        val (server, _) = identity()
        val (other, _) = identity("other")
        val serverKey = crypto.keys.encodePem(server.privateKey)
        val otherKey = crypto.keys.encodePem(other.privateKey)
        val chain = server.chain.joinToString("") { certificate -> certificates.encodePem(certificate) }

        suspend fun loaded(text: String): MaterialFailure? {
            material.stored[BUNDLE] = text.encodeToByteString()
            return loader.identity(IdentitySpec.PemBundle(BUNDLE)).failureOrNull()
        }
        loaded(chain) shouldBe MaterialFailure.NoKey
        loaded(chain + serverKey + otherKey) shouldBe MaterialFailure.AmbiguousKey
        loaded(serverKey) shouldBe MaterialFailure.NoCertificate
        loaded(chain + otherKey) shouldBe MaterialFailure.KeyMismatch
        loaded(chain + serverKey + "ä") shouldBe MaterialFailure.Malformed
        loaded(chain + BROKEN_KEY) shouldBe MaterialFailure.Malformed
        loaded(BROKEN_CERTIFICATE + serverKey) shouldBe MaterialFailure.Malformed
        loaded("not pem") shouldBe MaterialFailure.NoCertificate
    }

    test("sources report what they cannot give") {
        val material = MemoryMaterial()
        val loader = MaterialLoader(crypto, material, KeystoreLimits(maximumBytes = 4))
        loader.certificates(CHAIN).failureOrNull() shouldBe MaterialFailure.Missing
        material.stored[CHAIN] = ByteString()
        loader.certificates(CHAIN).failureOrNull() shouldBe MaterialFailure.NoCertificate
        material.stored[CHAIN] = FIVE_BYTES
        loader.certificates(CHAIN).failureOrNull() shouldBe MaterialFailure.TooLarge
        material.isUnavailable = true
        loader.anchors(CHAIN).failureOrNull() shouldBe MaterialFailure.Unavailable
        material.isUnavailable = false
        material.stored[STORE] = TRUNCATED
        loader.failureOf(IdentitySpec.KeyStore(STORE, password())) shouldBe MaterialFailure.Malformed
        val (server, _) = identity()
        val noP256 = Crypto(environment { policy = cryptoPolicy { curves(EllipticCurve.P384) } })
        material.stored[CHAIN] = server.certificate.encoded
        val restricted = MaterialLoader(noP256, material)
        restricted.anchors(CHAIN).failureOrNull() shouldBe MaterialFailure.Unsupported
        loader.toString() shouldContain "MaterialLoader"
        MaterialWriter(crypto, material).toString() shouldContain "MaterialWriter"
    }

    test("references, reads and specs show no secret") {
        shouldThrow<IllegalArgumentException> { MaterialRef(" ") }
        shouldThrow<IllegalArgumentException> { MaterialRef("x".repeat(TOO_LONG)) }
        MaterialRef("a\u0000b").toString() shouldNotContain "\u0000"
        val found = MaterialRead.Found(TWO_BYTES)
        found shouldBe MaterialRead.Found(TWO_BYTES)
        found shouldNotBe MaterialRead.Found(ByteString(1))
        found shouldNotBe TWO_BYTES
        found.hashCode() shouldBe TWO_BYTES.size
        found.toString() shouldBe "Found(size=2)"
        val spec = IdentitySpec.KeyStore(STORE, password(SECRET), alias = "a")
        spec.toString() shouldNotContain SECRET
        IdentitySpec.KeyStore(STORE, password()).toString() shouldContain "alias=none"
        val bundle = IdentitySpec.PemBundle(certificates = CHAIN, key = KEY, password = password(SECRET))
        bundle.toString() shouldContain "encrypted=true"
        IdentitySpec.PemBundle(CHAIN).key shouldBe CHAIN
        IdentitySpec.PemBundle(CHAIN).toString() shouldContain "encrypted=false"
    }
})
