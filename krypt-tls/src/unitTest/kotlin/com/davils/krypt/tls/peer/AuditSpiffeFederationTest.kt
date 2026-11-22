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

package com.davils.krypt.tls.peer

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.authority.profile.CertificateProfile
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.tls.ClientAuthentication
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.SPIFFE_ID
import com.davils.krypt.tls.fixture.connect
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.tls
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

class AuditSpiffeFederationTest : FunSpec({
    test("the authority of a federated trust domain cannot mint an id of the home trust domain by default") {
        val home = Pki.create("Home")
        val partner = Pki.create("Partner")
        val serverIdentity = home.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val id = checkNotNull(SpiffeId.parse(SPIFFE_ID).getOrNull())
        val server = TlsContext(
            tls(TlsRole.Server, crypto) {
                identities = listOf(serverIdentity)
                clientAuthentication = ClientAuthentication.Required
                trust { anchors = listOf(home.anchor, partner.anchor) }
                authorizer = SpiffeAuthorizer.ids(id)
            },
        )
        val forged = partner.custom(listOf(GeneralName.Uri(SPIFFE_ID))) {
            extendedKeyUsage(listOf(KeyPurposes.ClientAuth))
        }
        val client = TlsContext(
            tls(TlsRole.Client, crypto) {
                identities = listOf(forged)
                trust { anchors = listOf(home.anchor) }
            },
        )
        val connection = connect(client, server)
        println("AUDIT federation: established=${connection.isEstablished}")
        connection.isEstablished shouldBe false
    }
})
