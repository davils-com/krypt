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

package com.davils.krypt.tls

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.tls.fixture.OTHER_HOST
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.StubEngine
import com.davils.krypt.tls.fixture.StubSession
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.internal.JcaCertificates
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import com.davils.krypt.x509.name.GeneralName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val EC: String = "EC"
private const val RSA: String = "RSA"

private fun leafOf(manager: RotatingKeyManager, alias: String): Certificate {
    val chain = manager.getCertificateChain(alias).shouldNotBeNull()
    val decoded = Certificates(crypto).decode(ByteString(chain.single().encoded))
    return decoded.getOrNull().shouldNotBeNull()
}

class RotatingKeyManagerTest : FunSpec({
    test("a server alias is chosen by key type and server name") {
        val pki = Pki.create()
        val first = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val second = pki.identity(CertificateProfile.TlsServer, GeneralName.Dns(OTHER_HOST))
        val manager = TlsContext(serverConfiguration(pki, listOf(first, second))).keyManager
        val default = manager.chooseServerAlias(keyType = EC, issuers = null, socket = null).shouldNotBeNull()
        leafOf(manager, default) shouldBe first.certificate
        manager.getPrivateKey(default).shouldNotBeNull().algorithm shouldBe EC
        val engine = StubEngine(StubSession(staples = emptyList(), serverName = OTHER_HOST))
        val named = manager.chooseEngineServerAlias(keyType = EC, issuers = null, engine = engine).shouldNotBeNull()
        leafOf(manager, named) shouldBe second.certificate
        manager.chooseEngineServerAlias(keyType = EC, issuers = null, engine = null) shouldBe default
        manager.chooseServerAlias(keyType = RSA, issuers = null, socket = null).shouldBeNull()
        manager.chooseServerAlias(keyType = null, issuers = null, socket = null).shouldBeNull()
        manager.getServerAliases(EC, null).shouldNotBeNull().size shouldBe 2
        manager.getServerAliases(RSA, null).shouldBeNull()
        manager.getCertificateChain(null).shouldBeNull()
        manager.getPrivateKey("unknown").shouldBeNull()
        manager.toString() shouldContain "2 identities"
    }

    test("a client alias prefers an identity of an authority the server names") {
        val pki = Pki.create()
        val other = Pki.create("Other")
        val server = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val first = pki.identity(CertificateProfile.TlsClient)
        val second = other.identity(CertificateProfile.TlsClient)
        val manager = TlsContext(serverConfiguration(pki, listOf(server))).keyManager
        manager.rotate(listOf(first, second))
        val issuer = JcaCertificates.toJca(other.certificate).subjectX500Principal
        val chosen = manager.chooseClientAlias(arrayOf(EC), arrayOf(issuer), null).shouldNotBeNull()
        leafOf(manager, chosen) shouldBe second.certificate
        val fallback = manager.chooseEngineClientAlias(arrayOf(RSA, EC), null, null).shouldNotBeNull()
        leafOf(manager, fallback) shouldBe first.certificate
        manager.chooseClientAlias(null, null, null).shouldBeNull()
        manager.getClientAliases(EC, null).shouldNotBeNull().size shouldBe 2
    }

    test("an alias of the previous identities still resolves, one of older ones does not") {
        val pki = Pki.create()
        val first = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val second = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val manager = TlsContext(serverConfiguration(pki, listOf(first))).keyManager
        val old = manager.chooseServerAlias(keyType = EC, issuers = null, socket = null).shouldNotBeNull()
        manager.rotate(listOf(second))
        manager.getPrivateKey(old).shouldNotBeNull()
        manager.rotate(listOf(first))
        manager.getPrivateKey(old).shouldBeNull()
        shouldThrow<IllegalArgumentException> {
            manager.rotate(List(TlsConfiguration.HARD_MAXIMUM_IDENTITIES + 1) { first })
        }
    }
})
