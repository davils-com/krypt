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

package com.davils.krypt.cms.enveloped

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.der
import com.davils.krypt.cms.fixture.replaced
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val KEK_BYTES: Int = 32

private val identifier: ByteString = "kek".encodeToByteString()

private fun kek(): SecretKey = SecretKey.of(SecretBytes.copyOf(ByteArray(KEK_BYTES) { 1 }))

private fun oid(value: ObjectIdentifier): ByteString = der { objectIdentifier(value) }

private fun relabelled(encoded: ByteString, from: ObjectIdentifier, to: ObjectIdentifier): ByteString =
    replaced(encoded = encoded, old = oid(from), new = oid(to))

class AuthenticatedEnvelopedTest : FunSpec({
    test("authenticated enveloped data binds its content type") {
        val enveloped = cms.envelop(
            content = CONTENT,
            recipients = listOf(Recipient.Kek(identifier, kek())),
            encryption = ContentEncryption.Aes256Gcm,
            contentType = ContentTypes.SignedData,
        )
        val decoded = cms.decodeEnveloped(enveloped.encoded).value()
        decoded.contentType shouldBe ContentTypes.SignedData
        cms.decrypt(decoded, Credential.Kek(identifier, kek())).value() shouldBe CONTENT
        val changed = relabelled(enveloped.encoded, from = ContentTypes.SignedData, to = ContentTypes.Data)
        cms.decodeEnveloped(changed).failureOrNull() shouldBe CmsFailure.Malformed
    }

    test("authenticated enveloped data of a type other than id-data carries authenticated attributes") {
        val plain = cms.envelop(CONTENT, listOf(Recipient.Kek(identifier, kek())), ContentEncryption.Aes256Gcm)
        plain.authenticatedAttributes shouldBe null
        cms.decodeEnveloped(plain.encoded).value().contentType shouldBe ContentTypes.Data
        val typed = relabelled(plain.encoded, from = ContentTypes.Data, to = ContentTypes.SignedData)
        cms.decodeEnveloped(typed).failureOrNull() shouldBe CmsFailure.Malformed
    }
})
