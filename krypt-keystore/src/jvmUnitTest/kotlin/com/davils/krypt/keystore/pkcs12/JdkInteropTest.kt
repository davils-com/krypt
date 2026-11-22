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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretText
import com.davils.krypt.keystore.fixture.ITERATIONS
import com.davils.krypt.keystore.fixture.crypto
import com.davils.krypt.keystore.fixture.identity
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec

private const val PASSWORD: String = "interop"
private const val SERVER: String = "server"

class JdkInteropTest : FunSpec({
    test("the JDK reads what krypt writes") {
        val (server, root) = identity()
        val store = Pkcs12Store(
            keys = listOf(KeyEntry(server, alias = SERVER)),
            certificates = listOf(CertificateEntry(root.certificate, alias = "root", isTrusted = true)),
        )
        val encoded = Pkcs12(crypto).encode(store, SecretText.of(PASSWORD), iterations = ITERATIONS)
        val jdk = KeyStore.getInstance("PKCS12")
        jdk.load(ByteArrayInputStream(encoded.toByteArray()), PASSWORD.toCharArray())
        jdk.getKey(SERVER, PASSWORD.toCharArray()) shouldNotBe null
        jdk.getCertificateChain(SERVER).size shouldBe 2
        jdk.isCertificateEntry("root") shouldBe true
    }

    test("krypt reads what the JDK writes") {
        val (server, _) = identity()
        val factory = CertificateFactory.getInstance("X.509")
        val chain = server.chain.map { certificate ->
            factory.generateCertificate(ByteArrayInputStream(certificate.encoded.toByteArray()))
        }
        val pkcs8 = crypto.keys.encodePrivate(server.privateKey).use { encoded ->
            encoded.reveal { bytes -> bytes.copyOf() }
        }
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        val jdk = KeyStore.getInstance("PKCS12")
        jdk.load(null, null)
        jdk.setKeyEntry("jdk", key, PASSWORD.toCharArray(), chain.toTypedArray())
        val output = ByteArrayOutputStream()
        jdk.store(output, PASSWORD.toCharArray())
        val decoded = Pkcs12(crypto).decode(ByteString(output.toByteArray()), SecretText.of(PASSWORD))
        val entry = checkNotNull(decoded.getOrNull()).keys.single()
        entry.alias shouldBe "jdk"
        entry.identity shouldBe server
    }
})
