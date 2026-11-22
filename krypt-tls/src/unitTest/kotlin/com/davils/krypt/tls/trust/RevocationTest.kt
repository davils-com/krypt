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
import com.davils.krypt.ocsp.OcspResponseSource
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.fixture.Connection
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.clientConfiguration
import com.davils.krypt.tls.fixture.connect
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.fixture.serverConfiguration
import com.davils.krypt.tls.fixture.trustingClient
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.path.PinSet
import com.davils.krypt.x509.path.RevocationListSource
import com.davils.krypt.x509.path.RevocationStatus
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private fun failureOf(connection: Connection): TrustFailure? =
    connection.failures.firstNotNullOfOrNull { failure -> TrustFailure.of(failure) }

class RevocationTest : FunSpec({
    test("a client refuses a server its authority revoked by a revocation list, and caches the status") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        val cache = RevocationCache()
        val lists = mutableListOf(pki.revocationList())
        val client = trustingClient {
            anchors = listOf(pki.anchor)
            revocation = RevocationMode.HardFail
            revocationListSource = RevocationListSource { lists.toList() }
            this.cache = cache
        }
        connect(client, server).isEstablished shouldBe true
        pki.revoke(identity)
        cache.clear()
        lists[0] = pki.revocationList()
        failureOf(connect(client, server)) shouldBe TrustFailure.Revoked
        cache.status(identity.certificate, crypto.environment.clock.now()) shouldBe RevocationStatus.Revoked
        lists.clear()
        failureOf(connect(client, server)) shouldBe TrustFailure.Revoked
    }

    test("an unknown status passes with soft-fail and fails with hard-fail") {
        val pki = Pki.create()
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        val silent = OcspResponseSource { _, _, _ -> null }
        val soft = trustingClient {
            anchors = listOf(pki.anchor)
            ocspSource = silent
        }
        connect(soft, server).isEstablished shouldBe true
        val hard = trustingClient {
            anchors = listOf(pki.anchor)
            revocation = RevocationMode.HardFail
            ocspSource = OcspResponseSource { _, _, _ -> error("The responder is down") }
            revocationListSource = RevocationListSource { error("The list is gone") }
        }
        failureOf(connect(hard, server)) shouldBe TrustFailure.RevocationUnknown
        val off = trustingClient {
            anchors = listOf(pki.anchor)
            revocation = RevocationMode.Off
        }
        connect(off, server).isEstablished shouldBe true
    }

    test("a client refuses a must-staple server that staples nothing, unless revocation is off") {
        val pki = Pki.create()
        val identity = pki.custom(listOf(SERVER_NAME)) {
            extendedKeyUsage(listOf(KeyPurposes.ServerAuth))
            mustStaple()
        }
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        failureOf(connect(TlsContext(clientConfiguration(pki)), server)) shouldBe TrustFailure.MustStapleMissing
        val relaxed = trustingClient {
            anchors = listOf(pki.anchor)
            isMustStapleEnforced = false
        }
        connect(relaxed, server).isEstablished shouldBe true
    }

    test("pins are an extra condition on the validated path") {
        val pki = Pki.create()
        val other = Pki.create("Other")
        val identity = pki.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val server = TlsContext(serverConfiguration(pki, listOf(identity)))
        val pinned = PinSet.of(crypto, listOf(pki.certificate))
        val matching = trustingClient {
            anchors = listOf(pki.anchor)
            pins = pinned
        }
        connect(matching, server).isEstablished shouldBe true
        val foreign = PinSet.of(crypto, listOf(other.certificate))
        val mismatching = trustingClient {
            anchors = listOf(pki.anchor)
            pins = foreign
        }
        failureOf(connect(mismatching, server)) shouldBe TrustFailure.PinMismatch
    }
})
