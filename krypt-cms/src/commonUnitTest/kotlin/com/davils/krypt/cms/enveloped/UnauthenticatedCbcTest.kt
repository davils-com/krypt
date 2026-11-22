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
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.cms
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val KEY_BYTES: Int = 32

private val identifier: ByteString = "kek".encodeToByteString()

private fun key(): SecretKey = SecretKey.of(SecretBytes.copyOf(ByteArray(KEY_BYTES) { 1 }))

class UnauthenticatedCbcTest : FunSpec({
    test("enveloped data with AES-CBC is written and decrypted only with the opt-in") {
        val recipients = listOf(Recipient.Kek(identifier, key()))
        shouldThrow<IllegalArgumentException> { cms.envelop(CONTENT, recipients, ContentEncryption.Aes256Cbc) }
        val enveloped = cms.envelop(
            content = CONTENT,
            recipients = recipients,
            encryption = ContentEncryption.Aes256Cbc,
            isUnauthenticatedCbcAllowed = true,
        )
        val credential = Credential.Kek(identifier, key())
        cms.decrypt(enveloped, credential).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        cms.decrypt(enveloped, credential, isUnauthenticatedCbcAllowed = true).value() shouldBe CONTENT
        val authenticated = cms.envelop(CONTENT, recipients)
        cms.decrypt(authenticated, credential).value() shouldBe CONTENT
    }

    test("encrypted data is written and decrypted only with the opt-in") {
        shouldThrow<IllegalArgumentException> { cms.encrypt(CONTENT, key()) }
        val encrypted = cms.encrypt(CONTENT, key(), isUnauthenticatedCbcAllowed = true)
        cms.decrypt(encrypted, key()).failureOrNull() shouldBe CmsFailure.AlgorithmNotPermitted
        cms.decrypt(encrypted, key(), isUnauthenticatedCbcAllowed = true).value() shouldBe CONTENT
    }
})
