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

import com.davils.krypt.ct.LogList
import com.davils.krypt.ocsp.OcspResponseSource
import com.davils.krypt.tls.fixture.HOST
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.StubSession
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.peer.PeerIdentity
import com.davils.krypt.tls.peer.peerPolicy
import com.davils.krypt.tls.reload.ReloadSettings
import com.davils.krypt.tls.trust.RevocationCache
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.path.PinSet
import com.davils.krypt.x509.path.RevocationListSource
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.security.Security
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours

private const val SUN_JSSE: String = "SunJSSE"

class BoundsTest : FunSpec({
    test("the hard bounds are public constants") {
        TlsConfiguration.HARD_MAXIMUM_SESSION_TIMEOUT shouldBe 7.days
        RevocationCache.DEFAULT_LIFETIME shouldBe 1.hours
        RevocationCache.HARD_MAXIMUM_LIFETIME shouldBe 7.days
        ReloadSettings.HARD_MAXIMUM_DELAY shouldBe 1.hours
        ReloadSettings.HARD_MAXIMUM_WARNING shouldBe 365.days
    }

    test("every setting of the builders is kept and shown") {
        val pki = Pki.create()
        val jsse = Security.getProvider(SUN_JSSE)
        val pins = PinSet.of(crypto, listOf(pki.certificate))
        val configuration = tls(TlsRole.Client, crypto) {
            signatureSchemes = listOf(SignatureScheme.EcdsaSecp256r1Sha256)
            provider = jsse
            trust {
                anchors = listOf(pki.anchor)
                this.pins = pins
                ocspSource = OcspResponseSource { _, _, _ -> null }
                revocationListSource = RevocationListSource { emptyList() }
                cache = RevocationCache()
                limits = X509Limits.Default
                transparency(LogList(emptyList()))
            }
        }
        configuration.signatureSchemes shouldBe listOf(SignatureScheme.EcdsaSecp256r1Sha256)
        configuration.provider shouldBe jsse
        configuration.trust.toString() shouldContain "pins=true, revocation=SoftFail, ocspSource=true"
        configuration.trust.toString() shouldContain "cache=true, mustStaple=true, transparency=true"
        TlsContext(configuration).capabilities shouldBe TlsCapabilities.of(jsse)
        TlsCapabilities.of(jsse).namedGroups.first() shouldBe NamedGroup.X25519MlKem768
        peerPolicy { require { true } }.toString() shouldContain "predicate=true"
        val session = StubSession(staples = emptyList(), host = HOST)
        session.putValue(name = "com.davils.krypt.tls.peer", value = HOST)
        PeerIdentity.of(session).shouldBeNull()
    }
})
