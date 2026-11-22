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

package com.davils.krypt.tls.trust

import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.core.environment
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.fixture.Connection
import com.davils.krypt.tls.fixture.MovableClock
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.connect
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.tls
import com.davils.krypt.x509.path.RevocationListSource
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes

private fun failureOf(connection: Connection): TrustFailure? =
    connection.failures.firstNotNullOfOrNull { failure -> TrustFailure.of(failure) }

private fun clientOf(pki: Pki, clock: MovableClock, lifetime: Duration, source: RevocationListSource): TlsContext {
    val timed = Crypto(environment { this.clock = clock })
    return TlsContext(
        tls(TlsRole.Client, timed) {
            trust {
                anchors = listOf(pki.anchor)
                revocation = RevocationMode.HardFail
                revocationListSource = source
                cache = RevocationCache(lifetime = lifetime)
            }
        },
    )
}

class RevocationCacheExpiryTest : FunSpec({
    test("a cached status expires one lifetime after the source decided it, however often handshakes read it") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        val clock = MovableClock()
        val lists = mutableListOf(pki.revocationList())
        var fetches = 0
        val source = RevocationListSource { _ ->
            fetches += 1
            lists.toList()
        }
        val client = clientOf(pki = pki, clock = clock, lifetime = 10.minutes, source = source)
        connect(client, server).isEstablished shouldBe true
        clock.offset = 6.minutes
        connect(client, server).isEstablished shouldBe true
        fetches shouldBe 1
        pki.revoke(identity)
        lists[0] = pki.revocationList()
        clock.offset = 12.minutes
        failureOf(connect(client, server)) shouldBe TrustFailure.Revoked
        fetches shouldBe 2
    }

    test("a cached status expires at the next update of the revocation list it came from") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        val clock = MovableClock()
        val lists = mutableListOf(pki.revocationList(validity = 5.minutes))
        var fetches = 0
        val source = RevocationListSource { _ ->
            fetches += 1
            lists.toList()
        }
        val client = clientOf(pki = pki, clock = clock, lifetime = 1.hours, source = source)
        connect(client, server).isEstablished shouldBe true
        clock.offset = 4.minutes
        connect(client, server).isEstablished shouldBe true
        fetches shouldBe 1
        pki.revoke(identity)
        lists[0] = pki.revocationList()
        clock.offset = 6.minutes
        failureOf(connect(client, server)) shouldBe TrustFailure.Revoked
        fetches shouldBe 2
    }
})
