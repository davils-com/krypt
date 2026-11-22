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
        val bound = List(CmsLimits.MAXIMUM_PASSWORD_RECIPIENTS) { password(alice) }
        val enveloped = quick.envelop(CONTENT, bound)
        quick.decrypt(enveloped, Credential.Password(alice)).value() shouldBe CONTENT
        shouldThrow<IllegalArgumentException> { quick.envelop(CONTENT, bound + password(alice)) }
        val base = EnvelopedBase(enveloped)
        val recipients = enveloped.recipients.map { recipient -> recipient.encoded }
        val tooMany = base.withRecipients((recipients + recipients.first()).sortedWith(derOrder))
        val decoded = quick.decodeEnveloped(tooMany).value()
        quick.decrypt(decoded, Credential.Password(alice)).failureOrNull() shouldBe CmsFailure.Malformed
        val kek = SecretKey.of(SecretBytes.copyOf(ByteArray(KEK_BYTES) { 1 }))
        val identifier = "kek".encodeToByteString()
        quick.decrypt(decoded, Credential.Kek(identifier, kek)).failureOrNull() shouldBe CmsFailure.Malformed
    }

    test("a password derives once per message, with the first password recipient") {
        val enveloped = quick.envelop(CONTENT, listOf(password(alice), password(bob)))
        quick.decrypt(enveloped, Credential.Password(alice)).value() shouldBe CONTENT
        quick.decrypt(enveloped, Credential.Password(bob)).failureOrNull() shouldBe CmsFailure.DecryptionFailed
        val kek = SecretKey.of(SecretBytes.copyOf(ByteArray(KEK_BYTES) { 1 }))
        val identifier = "kek".encodeToByteString()
        val mixed = quick.envelop(CONTENT, listOf(Recipient.Kek(identifier, kek), password(bob)))
        quick.decrypt(mixed, Credential.Password(bob)).value() shouldBe CONTENT
        quick.decrypt(mixed, Credential.Kek(identifier, kek)).value() shouldBe CONTENT
    }
})
