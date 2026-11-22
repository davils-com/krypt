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

package com.davils.krypt.keystore.pkcs12

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.keystore.KeystoreFailure
import com.davils.krypt.keystore.KeystoreLimits
import com.davils.krypt.keystore.fixture.CA_PEM
import com.davils.krypt.keystore.fixture.ITERATIONS
import com.davils.krypt.keystore.fixture.JDK_STORE
import com.davils.krypt.keystore.fixture.LEAF_PEM
import com.davils.krypt.keystore.fixture.OPENSSL_CLASSIC
import com.davils.krypt.keystore.fixture.OPENSSL_LEGACY
import com.davils.krypt.keystore.fixture.OPENSSL_PBMAC1
import com.davils.krypt.keystore.fixture.certificates
import com.davils.krypt.keystore.fixture.crypto
import com.davils.krypt.keystore.fixture.identity
import com.davils.krypt.keystore.fixture.password
import com.davils.krypt.primitive.Crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val ALIAS: String = "leaf"
private const val SERVER: String = "server"

private suspend fun failureOf(pkcs12: Pkcs12, file: ByteString, secret: String = "fixture"): KeystoreFailure? =
    pkcs12.decode(file, password(secret)).failureOrNull()

private fun flipped(bytes: ByteString, index: Int): ByteString {
    val array = bytes.toByteArray()
    array[index] = (array[index].toInt() xor 1).toByte()
    return ByteString(array)
}

class Pkcs12Test : FunSpec({
    val pkcs12 = Pkcs12(crypto)

    test("files of OpenSSL and the JDK are read with their chains") {
        val leaf = checkNotNull(certificates.decodePem(LEAF_PEM).getOrNull()).single()
        val ca = checkNotNull(certificates.decodePem(CA_PEM).getOrNull()).single()
        listOf(OPENSSL_CLASSIC, OPENSSL_PBMAC1, JDK_STORE).forEach { file ->
            val store = checkNotNull(pkcs12.decode(file, password()).getOrNull())
            val entry = store.keys.single()
            entry.alias shouldBe ALIAS
            entry.identity.chain shouldBe listOf(leaf, ca)
            store.key(ALIAS) shouldBe entry
            store.key("other") shouldBe null
        }
        val jdk = checkNotNull(pkcs12.decode(JDK_STORE, password()).getOrNull())
        jdk.certificates shouldBe listOf(CertificateEntry(ca, alias = "anchor", isTrusted = true))
    }

    test("legacy protection is unsupported and a wrong password or a changed byte fails") {
        pkcs12.decode(OPENSSL_LEGACY, password()).failureOrNull() shouldBe KeystoreFailure.Unsupported
        listOf(OPENSSL_CLASSIC, OPENSSL_PBMAC1).forEach { file ->
            failureOf(pkcs12, file, secret = "wrong") shouldBe KeystoreFailure.WrongPassword
            failureOf(pkcs12, flipped(file, file.size / 2)) shouldBe KeystoreFailure.WrongPassword
        }
    }

    test("stores round trip with keys, chains and trusted certificates") {
        val (server, root) = identity(SERVER)
        val (client, _) = identity("client")
        val store = Pkcs12Store(
            keys = listOf(KeyEntry(server, alias = SERVER), KeyEntry(client)),
            certificates = listOf(
                CertificateEntry(root.certificate, alias = "root", isTrusted = true),
                CertificateEntry(client.chain.last()),
            ),
        )
        val encoded = pkcs12.encode(store, password(), iterations = ITERATIONS)
        val decoded = checkNotNull(pkcs12.decode(encoded, password()).getOrNull())
        decoded.keys shouldBe store.keys
        decoded.certificates shouldBe listOf(CertificateEntry(root.certificate, alias = "root", isTrusted = true))
        val first = decoded.keys.first()
        val key = first.identity.privateKey
        crypto.keys.pair(key, checkNotNull(server.certificate.publicKey)) shouldNotBe null
        val empty = pkcs12.encode(Pkcs12Store(), password())
        pkcs12.decode(empty, password()).getOrNull() shouldBe Pkcs12Store()
        shouldThrow<IllegalArgumentException> { pkcs12.encode(Pkcs12Store(), password(""), iterations = ITERATIONS) }
    }

    test("values compare every field and show no secret") {
        val (server, root) = identity(SERVER)
        val entry = KeyEntry(server, alias = SERVER)
        entry shouldBe KeyEntry(server, alias = SERVER)
        entry shouldNotBe KeyEntry(server)
        entry shouldNotBe KeyEntry(identity("other").first, alias = SERVER)
        entry shouldNotBe SERVER
        entry.hashCode() shouldBe KeyEntry(server, alias = SERVER).hashCode()
        entry.toString() shouldContain SERVER
        KeyEntry(server).toString() shouldContain "none"
        val certificate = CertificateEntry(root.certificate, alias = "root", isTrusted = true)
        certificate shouldNotBe CertificateEntry(root.certificate, alias = "root")
        certificate shouldNotBe SERVER
        certificate shouldNotBe CertificateEntry(root.certificate, isTrusted = true)
        certificate shouldNotBe CertificateEntry(server.certificate, alias = "root", isTrusted = true)
        certificate.hashCode() shouldBe CertificateEntry(root.certificate, alias = "root", isTrusted = true).hashCode()
        certificate.toString() shouldContain "trusted=true"
        CertificateEntry(root.certificate).toString() shouldContain "none"
        val store = Pkcs12Store(keys = listOf(entry))
        store shouldNotBe Pkcs12Store()
        store shouldNotBe SERVER
        store shouldNotBe Pkcs12Store(keys = listOf(entry), certificates = listOf(certificate))
        store.hashCode() shouldBe Pkcs12Store(keys = listOf(entry)).hashCode()
        store.toString() shouldContain "keys="
        pkcs12.toString() shouldContain "Pkcs12"
    }

    test("limits and the policy bound the work") {
        val small = Pkcs12(crypto, KeystoreLimits(maximumBytes = 100))
        failureOf(small, OPENSSL_CLASSIC) shouldBe KeystoreFailure.Malformed
        val few = Pkcs12(crypto, KeystoreLimits(maximumEntries = 1))
        failureOf(few, OPENSSL_CLASSIC) shouldBe KeystoreFailure.Malformed
        val twoBags = Pkcs12(crypto, KeystoreLimits(maximumEntries = 2))
        failureOf(twoBags, OPENSSL_CLASSIC) shouldBe KeystoreFailure.Malformed
        val noHmac = Pkcs12(Crypto(environment { policy = cryptoPolicy { forbid(MacAlgorithm.HmacSha256) } }))
        failureOf(noHmac, OPENSSL_PBMAC1) shouldBe KeystoreFailure.Refused
        failureOf(noHmac, OPENSSL_CLASSIC) shouldBe KeystoreFailure.Refused
        val fewIterations = Pkcs12(crypto, KeystoreLimits(maximumMacIterations = 100))
        failureOf(fewIterations, OPENSSL_CLASSIC) shouldBe KeystoreFailure.Refused
        val strict = Pkcs12(Crypto(environment { policy = cryptoPolicy { minimumVerifiedIterations = 4_096 } }))
        failureOf(strict, OPENSSL_PBMAC1) shouldBe KeystoreFailure.Refused
        failureOf(strict, OPENSSL_CLASSIC) shouldBe KeystoreFailure.Refused
        val cnsa = Pkcs12(Crypto(environment { policy = CryptoPolicy.Cnsa2 }))
        failureOf(cnsa, OPENSSL_PBMAC1) shouldBe KeystoreFailure.Refused
    }
})
