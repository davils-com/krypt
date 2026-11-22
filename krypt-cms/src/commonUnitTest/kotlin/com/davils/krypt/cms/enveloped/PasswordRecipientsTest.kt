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
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.CmsLimits
import com.davils.krypt.cms.fixture.CONTENT
import com.davils.krypt.cms.fixture.EnvelopedBase
import com.davils.krypt.cms.fixture.value
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

private const val ITERATIONS: Int = 1_000
private const val KEK_BYTES: Int = 32

private val quick: Cms = Cms(
    Crypto(
        environment {
            policy = cryptoPolicy {
                minimumIterations = ITERATIONS
                minimumVerifiedIterations = ITERATIONS
            }
        },
    ),
)

private val alice: SecretText = SecretText.of("alice's password")

private val bob: SecretText = SecretText.of("bob's password")

private val kek: SecretKey = SecretKey.of(SecretBytes.copyOf(ByteArray(KEK_BYTES) { 1 }))

private val identifier: ByteString = "kek".encodeToByteString()

private fun password(text: SecretText): Recipient = Recipient.Password(text, ITERATIONS)

private fun unsigned(bytes: ByteString): List<Int> = bytes.toByteArray().map { byte -> byte.toUByte().toInt() }

private val derOrder: Comparator<ByteString> = Comparator { first, second ->
    val left = unsigned(first)
    val right = unsigned(second)
    val differing = left.zip(right).firstOrNull { (one, other) -> one != other }
    differing?.let { (one, other) -> one.compareTo(other) } ?: left.size.compareTo(right.size)
}

class PasswordRecipientsTest : FunSpec({
    test("a message names at most the bound of password recipients") {
        val enveloped = quick.envelop(CONTENT, listOf(password(alice)))
        quick.decrypt(enveloped, Credential.Password(alice)).value() shouldBe CONTENT
        shouldThrow<IllegalArgumentException> { quick.envelop(CONTENT, listOf(password(alice), password(bob))) }
        val base = EnvelopedBase(enveloped)
        val recipient = enveloped.recipients.single().encoded
        val bound = base.withRecipients(List(CmsLimits.MAXIMUM_PASSWORD_RECIPIENTS) { recipient })
        quick.decrypt(quick.decodeEnveloped(bound).value(), Credential.Password(alice)).value() shouldBe CONTENT
        val tooMany = base.withRecipients(List(CmsLimits.MAXIMUM_PASSWORD_RECIPIENTS + 1) { recipient })
        val decoded = quick.decodeEnveloped(tooMany).value()
        quick.decrypt(decoded, Credential.Password(alice)).failureOrNull() shouldBe CmsFailure.Malformed
        quick.decrypt(decoded, Credential.Kek(identifier, kek)).failureOrNull() shouldBe CmsFailure.Malformed
    }

    test("a password derives once per message, with the first password recipient") {
        val enveloped = quick.envelop(CONTENT, listOf(password(alice)))
        val genuine = enveloped.recipients.single().encoded
        val bytes = genuine.toByteArray()
        val last = bytes.last()
        bytes[bytes.size - 1] = (last - 1).toByte().takeIf { last != 0.toByte() } ?: 1
        val ordered = listOf(genuine, ByteString(bytes)).sortedWith(derOrder)
        val both = quick.decodeEnveloped(EnvelopedBase(enveloped).withRecipients(ordered)).value()
        val isOpened = quick.decrypt(both, Credential.Password(alice)).failureOrNull() == null
        isOpened shouldBe (ordered.first() == genuine)
        val mixed = quick.envelop(CONTENT, listOf(Recipient.Kek(identifier, kek), password(bob)))
        quick.decrypt(mixed, Credential.Password(bob)).value() shouldBe CONTENT
        quick.decrypt(mixed, Credential.Kek(identifier, kek)).value() shouldBe CONTENT
    }
})
