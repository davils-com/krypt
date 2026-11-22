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
import com.davils.krypt.spiffe.TrustDomain
import com.davils.krypt.spiffe.bundle.BundleSet
import com.davils.krypt.spiffe.bundle.TrustBundle
import com.davils.krypt.tls.ClientAuthentication
import com.davils.krypt.tls.TlsContext
import com.davils.krypt.tls.TlsRole
import com.davils.krypt.tls.fixture.Connection
import com.davils.krypt.tls.fixture.FOREIGN_ID
import com.davils.krypt.tls.fixture.Pki
import com.davils.krypt.tls.fixture.SERVER_NAME
import com.davils.krypt.tls.fixture.SPIFFE_ID
import com.davils.krypt.tls.fixture.connect
import com.davils.krypt.tls.fixture.crypto
import com.davils.krypt.tls.tls
import com.davils.krypt.tls.trust.TrustFailure
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.name.GeneralName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private suspend fun clientOf(minter: Pki, home: Pki, id: String): TlsContext {
    val identity = minter.custom(listOf(GeneralName.Uri(id))) {
        extendedKeyUsage(listOf(KeyPurposes.ClientAuth))
    }
    return TlsContext(
        tls(TlsRole.Client, crypto) {
            identities = listOf(identity)
            trust { anchors = listOf(home.anchor) }
        },
    )
}

private fun failureOf(connection: Connection): TrustFailure? =
    connection.failures.firstNotNullOfOrNull { failure -> TrustFailure.of(failure) }

class SpiffeFederationTest : FunSpec({
    test("the authority of a federated trust domain cannot vouch for an id of the home trust domain") {
        val home = Pki.create("Home")
        val partner = Pki.create("Partner")
        val serverIdentity = home.identity(CertificateProfile.TlsServer, SERVER_NAME)
        val bundles = BundleSet(
            listOf(
                TrustBundle(TrustDomain.of("example.org"), x509Authorities = listOf(home.certificate)),
                TrustBundle(TrustDomain.of("example.com"), x509Authorities = listOf(partner.certificate)),
            ),
        )
        val homeId = checkNotNull(SpiffeId.parse(SPIFFE_ID).getOrNull())
        val partnerId = checkNotNull(SpiffeId.parse(FOREIGN_ID).getOrNull())
        val server = TlsContext(
            tls(TlsRole.Server, crypto) {
                identities = listOf(serverIdentity)
                clientAuthentication = ClientAuthentication.Required
                trust { anchors = listOf(home.anchor, partner.anchor) }
                authorizer = SpiffeAuthorizer.ids(bundles, homeId, partnerId)
            },
        )
        val forged = connect(clientOf(minter = partner, home = home, id = SPIFFE_ID), server)
        forged.isEstablished shouldBe false
        failureOf(forged) shouldBe TrustFailure.Unauthorized
        connect(clientOf(minter = home, home = home, id = SPIFFE_ID), server).isEstablished shouldBe true
        connect(clientOf(minter = partner, home = home, id = FOREIGN_ID), server).isEstablished shouldBe true
    }
})
