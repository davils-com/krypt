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

import com.davils.kore.core.validation.report.ValidationException
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.core.provider
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.fixture.H2
import com.davils.krypt.tls.fixture.HOST
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.crypto
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.security.Security
import kotlin.time.Duration

private const val TOO_LONG_PROTOCOL: Int = 256
private const val LOOPBACK: String = "127.0.0.1"
private const val SUN_JSSE: String = "SunJSSE"
private const val SUN: String = "SUN"
private const val IDENTITIES: String = "identities"
private const val TRUST: String = "trust"
private const val PROTOCOLS: String = "applicationProtocols"

private fun client(configure: TlsConfigurationBuilder.() -> Unit): TlsConfiguration = tls(TlsRole.Client, crypto) {
    trust { isSystemIncluded = true }
    configure()
}

private fun refuses(configure: TlsConfigurationBuilder.() -> Unit): String =
    shouldThrow<ValidationException> { client(configure) }.message

class TlsConfigurationTest : FunSpec({
    test("a client offers TLS 1.3 with every suite, group and scheme the policy permits") {
        val configuration = client {
            applicationProtocols = listOf(H2)
            serverName = HOST
        }
        configuration.role shouldBe TlsRole.Client
        configuration.versions shouldContainExactly listOf(TlsVersion.Tls13)
        configuration.cipherSuites.map { suite -> suite.version }.toSet() shouldBe setOf(TlsVersion.Tls13)
        configuration.namedGroups.first() shouldBe NamedGroup.X25519MlKem768
        configuration.signatureSchemes shouldContainExactly SignatureScheme.entries
        configuration.isHostnameVerified shouldBe true
        configuration.provider.shouldBeNull()
        configuration.toString() shouldContain "Client"
        client { isTls12Enabled = true }.cipherSuites shouldContainExactly CipherSuite.entries
        client { serverName = LOOPBACK }.serverName shouldBe LOOPBACK
    }

    test("the crypto policy narrows the allowlists") {
        val strict = Crypto(environment { policy = CryptoPolicy.Cnsa2 })
        val configuration = tls(TlsRole.Client, strict) { trust { isSystemIncluded = true } }
        configuration.cipherSuites shouldNotContain CipherSuite.ChaCha20Poly1305Sha256
        configuration.cipherSuites shouldNotContain CipherSuite.Aes128GcmSha256
        configuration.namedGroups shouldNotContain NamedGroup.X25519
        val refused = shouldThrow<ValidationException> {
            tls(TlsRole.Client, strict) {
                trust { isSystemIncluded = true }
                cipherSuites = listOf(CipherSuite.ChaCha20Poly1305Sha256)
                namedGroups = listOf(NamedGroup.X25519)
                signatureSchemes = listOf(SignatureScheme.Ed25519)
            }
        }
        refused.message shouldContain "cipherSuites"
    }

    test("the JSSE provider of the environment is taken only if it offers TLS 1.3") {
        val jsse = Security.getProvider(SUN_JSSE)
        tls(TlsRole.Client, Crypto(environment { provider(jsse) })) { trust { isSystemIncluded = true } }
            .provider shouldBe jsse
        tls(TlsRole.Client, Crypto(environment { provider(Security.getProvider(SUN)) })) {
            trust { isSystemIncluded = true }
        }.provider.shouldBeNull()
    }

    test("bad settings are refused") {
        refuses { applicationProtocols = listOf("") } shouldContain PROTOCOLS
        refuses { applicationProtocols = listOf("x".repeat(TOO_LONG_PROTOCOL)) } shouldContain PROTOCOLS
        refuses { applicationProtocols = List(TlsConfiguration.HARD_MAXIMUM_PROTOCOLS + 1) { H2 } } shouldContain
            PROTOCOLS
        refuses { serverName = "-bad-.example" } shouldContain "serverName"
        refuses { sessionCacheSize = 0 } shouldContain "sessionCacheSize"
        refuses { sessionTimeout = Duration.ZERO } shouldContain "sessionTimeout"
        refuses { clientAuthentication = ClientAuthentication.Requested } shouldContain "clientAuthentication"
        shouldThrow<ValidationException> { tls(TlsRole.Client, crypto) {} }.message shouldContain TRUST
        shouldThrow<ValidationException> { tls(TlsRole.Server, crypto) {} }.message shouldContain
            IDENTITIES
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        refuses { identities = List(TlsConfiguration.HARD_MAXIMUM_IDENTITIES + 1) { identity } } shouldContain
            IDENTITIES
        tls(TlsRole.Server, crypto) { identities = listOf(identity) }.trust.anchors shouldBe emptyList()
        shouldThrow<ValidationException> {
            tls(TlsRole.Server, crypto) {
                identities = listOf(identity)
                clientAuthentication = ClientAuthentication.Required
            }
        }.message shouldContain TRUST
    }
})
