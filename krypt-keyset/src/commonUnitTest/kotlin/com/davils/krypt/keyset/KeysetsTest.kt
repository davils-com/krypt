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

package com.davils.krypt.keyset

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.audit.AuditEntry
import com.davils.krypt.core.audit.AuditRefusedException
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.CryptoPolicy
import com.davils.krypt.keyset.fixture.auditedKeysets
import com.davils.krypt.keyset.fixture.crypto
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.keyset.fixture.refusingKeysets
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.PolicyViolationException
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.yield

private const val THREE: Int = 3

class KeysetsTest : FunSpec({
    test("a generated key set has one enabled primary key") {
        val keyset = keysets.generate(KeyPurpose.Aead())
        keyset.keys.size shouldBe 1
        keyset.primary.status shouldBe KeyStatus.Enabled
        keyset.primary.isUsable shouldBe true
        keyset.isPublic shouldBe false
        keyset[keyset.primaryId] shouldBe keyset.primary
        keyset.toString() shouldBe "Keyset(Aead(AES-256-GCM), primary=${keyset.primaryId}, keys=1)"
        keyset.primary.toString() shouldContain keyset.primaryId.hex
        keyset.primary.toString() shouldNotContain "secret"
        keyset.hashCode() shouldBe keyset.hashCode()
        keyset shouldNotBe keysets.generate(KeyPurpose.Aead())
    }

    test("rotation, staging and promotion change the primary key without losing the old ones") {
        val first = keysets.generate(KeyPurpose.Mac())
        val rotated = keysets.rotate(first)
        rotated.keys.size shouldBe 2
        rotated.primaryId shouldNotBe first.primaryId
        rotated[first.primaryId]?.status shouldBe KeyStatus.Enabled
        val staged = keysets.add(rotated)
        staged.primaryId shouldBe rotated.primaryId
        staged.keys.size shouldBe THREE
        val newest = staged.keys.last().id
        val promoted = keysets.promote(staged, newest)
        promoted.primaryId shouldBe newest
        shouldThrow<IllegalArgumentException> {
            keysets.promote(
                staged,
                checkNotNull(KeyId.parseOrNull("0000000000000000")),
            )
        }
    }

    test("keys are disabled, enabled again and destroyed, never the primary key") {
        val keyset = keysets.rotate(keysets.generate(KeyPurpose.Aead()))
        val old = keyset.keys.first()
        val disabled = keysets.disable(keyset, old.id)
        disabled[old.id]?.status shouldBe KeyStatus.Disabled
        disabled[old.id]?.isUsable shouldBe false
        shouldThrow<IllegalArgumentException> { keysets.promote(disabled, old.id) }
        shouldThrow<IllegalArgumentException> { keysets.disable(disabled, old.id) }
        shouldThrow<IllegalArgumentException> { keysets.disable(disabled, disabled.primaryId) }
        shouldThrow<IllegalArgumentException> { keysets.enable(keyset, old.id) }
        keysets.enable(disabled, old.id)[old.id]?.status shouldBe KeyStatus.Enabled
        val destroyed = keysets.destroy(disabled, old.id)
        destroyed[old.id]?.status shouldBe KeyStatus.Destroyed
        old.secret?.isDestroyed shouldBe true
        shouldThrow<IllegalArgumentException> { keysets.destroy(destroyed, old.id) }
        shouldThrow<IllegalArgumentException> { keysets.destroy(destroyed, destroyed.primaryId) }
        keysets.prune(destroyed).keys shouldBe listOf(destroyed.primary)
    }

    test("asymmetric key sets have a public part that cannot change") {
        val keyset = keysets.generate(KeyPurpose.Signing())
        val public = keysets.publicKeyset(keyset)
        public.isPublic shouldBe true
        public.primary.publicKey shouldBe keyset.primary.publicKey
        public.primary.privateKey shouldBe null
        shouldThrow<IllegalArgumentException> { keysets.rotate(public) }
        shouldThrow<IllegalArgumentException> { keysets.publicKeyset(keysets.generate(KeyPurpose.Mac())) }
        val destroyed = keysets.destroy(keysets.rotate(keyset), keyset.primaryId)
        destroyed[keyset.primaryId]?.status shouldBe KeyStatus.Destroyed
        keyset.primary.privateKey?.isDestroyed shouldBe true
    }

    test("a full key set takes no new key") {
        val small = Keysets(crypto = crypto, limits = KeysetLimits(maximumKeys = 1))
        val keyset = small.generate(KeyPurpose.Aead())
        shouldThrow<IllegalArgumentException> { small.rotate(keyset) }
        small.toString() shouldContain "maximumKeys=1"
    }

    test("every change is audited and sent as an event") {
        val entries = mutableListOf<AuditEntry>()
        val audited = auditedKeysets(entries)
        coroutineScope {
            val events = async { audited.events.take(2).toList() }
            yield()
            val keyset = audited.generate(KeyPurpose.Aead())
            audited.rotate(keyset)
            events.await().map { event -> event.action } shouldBe listOf(KeysetAction.Generated, KeysetAction.Rotated)
            events.await().first().keyId shouldBe keyset.primaryId
        }
        entries.map { entry -> entry.action } shouldBe listOf(KeysetAction.Generated.audit, KeysetAction.Rotated.audit)
        entries.first().attributes shouldBe mapOf("purpose" to "Aead(AES-256-GCM)")
    }

    test("events compare by action and key") {
        coroutineScope {
            val event = async { keysets.events.first() }
            yield()
            val keyset = keysets.generate(KeyPurpose.Aead())
            val received = event.await()
            received shouldBe KeysetEvent(action = KeysetAction.Generated, keyId = keyset.primaryId)
            received shouldNotBe KeysetEvent(action = KeysetAction.Added, keyId = keyset.primaryId)
            received.hashCode() shouldBe listOf(KeysetAction.Generated, keyset.primaryId).hashCode()
            received.toString() shouldBe "KeysetEvent(Generated, ${keyset.primaryId})"
            received.component shouldBe "keyset"
        }
    }

    test("a required audit that cannot record refuses the change") {
        shouldThrow<AuditRefusedException> { refusingKeysets().generate(KeyPurpose.Aead()) }
    }

    test("the policy decides which keys are generated") {
        val cnsa = Keysets(Crypto(environment { policy = CryptoPolicy.Cnsa2 }))
        shouldThrow<PolicyViolationException> { cnsa.generate(KeyPurpose.Aead(AeadAlgorithm.Aes128Gcm)) }
        shouldThrow<PolicyViolationException> { cnsa.generate(KeyPurpose.Signing(KeyType.P256)) }
        cnsa.generate(KeyPurpose.Aead()).keys.size shouldBe 1
    }
})
