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

package com.davils.krypt.cms.signed

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.Pki
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.refusal
import com.davils.krypt.cms.fixture.replaced
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.cms.fixture.verified
import com.davils.krypt.core.algorithm.KeyType
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private val DIGESTED_DATA: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.7.5")

private fun oid(value: ObjectIdentifier): ByteString = der { objectIdentifier(value) }

class SignedContentTypeTest : FunSpec({
    test("a signer without signed attributes is accepted for id-data only") {
        val pki = Pki.create()
        val identity = pki.issue(KeyType.P256, "signer")
        val signed = cms.sign(CONTENT) {
            signer(identity.signer, identity.certificate) { isSignedAttributesUsed = false }
        }
        cms.verified(signed, parameters = pki.parameters).size shouldBe 1
        val data = oid(ContentTypes.Data)
        val relabelled = replaced(encoded = signed.encoded, old = data, new = oid(ContentTypes.SignedData))
        val decoded = cms.decodeSigned(relabelled).value()
        decoded.contentType shouldBe ContentTypes.SignedData
        cms.refusal(decoded, parameters = pki.parameters) shouldBe CmsFailure.AttributeMismatch
        shouldThrow<IllegalArgumentException> {
            cms.sign(CONTENT) {
                contentType = ContentTypes.SignedData
                signer(identity.signer, identity.certificate) { isSignedAttributesUsed = false }
            }
        }
    }

    test("signed attributes bind the content type") {
        val pki = Pki.create()
        val identity = pki.issue(KeyType.P256, "signer")
        val signed = cms.sign(CONTENT) {
            contentType = DIGESTED_DATA
            signer(identity.signer, identity.certificate)
        }
        cms.verified(signed, parameters = pki.parameters).size shouldBe 1
        val relabelled = replaced(encoded = signed.encoded, old = oid(DIGESTED_DATA), new = oid(ContentTypes.Data))
        cms.refusal(cms.decodeSigned(relabelled).value(), parameters = pki.parameters) shouldBe
            CmsFailure.AttributeMismatch
    }
})
