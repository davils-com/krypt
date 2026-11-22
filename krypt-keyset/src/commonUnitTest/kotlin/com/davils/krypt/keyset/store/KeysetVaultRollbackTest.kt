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

package com.davils.krypt.keyset.store

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.KeysetFailure
import com.davils.krypt.keyset.fixture.MemoryLedger
import com.davils.krypt.keyset.fixture.MemoryRepository
import com.davils.krypt.keyset.fixture.SwitchableKms
import com.davils.krypt.keyset.fixture.crypto
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.keyset.kms.LocalKms
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private const val NAME: String = "payments"
private const val AFTER_DELETION: Long = 3L

class KeysetVaultRollbackTest : FunSpec({
    val kms = LocalKms(crypto, crypto.keys.generateSecret())

    test("an old key set put back under the current revision cannot bring a destroyed key back") {
        val repository = MemoryRepository()
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms)
        val created = checkNotNull(vault.create(NAME, KeyPurpose.Aead()).getOrNull())
        val old = repository.stored.getValue(NAME)
        vault.update(NAME) { keyset -> keysets.destroy(keysets.rotate(keyset), created.primaryId) }
        val current = repository.stored.getValue(NAME)
        repository.stored[NAME] = StoredKeyset(revision = current.revision, encrypted = old.encrypted)
        vault.load(NAME) shouldBe Outcome.Failure(KeysetFailure.DecryptionFailed)
    }

    test("without a ledger an old revision put back whole is accepted, as documented") {
        val repository = MemoryRepository()
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms)
        val created = checkNotNull(vault.create(NAME, KeyPurpose.Aead()).getOrNull())
        val old = repository.stored.getValue(NAME)
        vault.update(NAME) { keyset -> keysets.rotate(keyset) }
        repository.stored[NAME] = old
        vault.load(NAME).getOrNull() shouldBe created
    }

    test("with a ledger an old revision put back whole is a rollback") {
        val repository = MemoryRepository()
        val ledger = MemoryLedger()
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms, ledger = ledger)
        val created = checkNotNull(vault.create(NAME, KeyPurpose.Aead()).getOrNull())
        ledger.revisions[NAME] shouldBe 1L
        val old = repository.stored.getValue(NAME)
        vault.update(NAME) { keyset -> keysets.destroy(keysets.rotate(keyset), created.primaryId) }
        ledger.revisions[NAME] shouldBe 2L
        repository.stored[NAME] = old
        vault.load(NAME) shouldBe Outcome.Failure(KeysetFailure.Rollback)
        vault.update(NAME) { keyset -> keyset } shouldBe Outcome.Failure(KeysetFailure.Rollback)
    }

    test("with a ledger a deleted key set that reappears is a rollback, and a new one starts after it") {
        val repository = MemoryRepository()
        val ledger = MemoryLedger()
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms, ledger = ledger)
        vault.create(NAME, KeyPurpose.Aead())
        val deleted = repository.stored.getValue(NAME)
        vault.delete(NAME) shouldBe true
        ledger.revisions[NAME] shouldBe 2L
        repository.stored[NAME] = deleted
        vault.load(NAME) shouldBe Outcome.Failure(KeysetFailure.Rollback)
        repository.stored.remove(NAME)
        val again = checkNotNull(vault.create(NAME, KeyPurpose.Aead()).getOrNull())
        repository.stored.getValue(NAME).revision shouldBe AFTER_DELETION
        vault.load(NAME).getOrNull() shouldBe again
        vault.delete("unknown") shouldBe false
        ledger.revisions["unknown"] shouldBe 1L
    }

    test("a ledger that fell behind or never saw the name catches up when the key set is read") {
        val repository = MemoryRepository()
        val ledger = MemoryLedger()
        KeysetVault(keysets = keysets, repository = repository, kms = kms).create(NAME, KeyPurpose.Aead())
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms, ledger = ledger)
        checkNotNull(vault.load(NAME).getOrNull())
        ledger.revisions[NAME] shouldBe 1L
        ledger.isRefusing = true
        checkNotNull(vault.update(NAME) { keyset -> keysets.rotate(keyset) }.getOrNull())
        ledger.revisions[NAME] shouldBe 1L
        ledger.isRefusing = false
        checkNotNull(vault.load(NAME).getOrNull())
        ledger.revisions[NAME] shouldBe 2L
    }

    test("a ledger that keeps refusing stops a deletion") {
        val repository = MemoryRepository()
        val ledger = MemoryLedger()
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms, ledger = ledger)
        vault.create(NAME, KeyPurpose.Aead())
        ledger.isRefusing = true
        shouldThrow<IllegalStateException> { vault.delete(NAME) }
        ledger.isFailing = true
        shouldThrow<IllegalStateException> { vault.delete(NAME) }
        repository.stored.keys shouldBe setOf(NAME)
    }

    test("what the repository, the ledger and the service throw becomes unavailable") {
        val repository = MemoryRepository()
        val ledger = MemoryLedger()
        val switchable = SwitchableKms(kms)
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = switchable, ledger = ledger)
        vault.create(NAME, KeyPurpose.Aead())
        switchable.isFailing = true
        vault.load(NAME).failureOrNull() shouldBe KeysetFailure.Unavailable
        vault.create("other", KeyPurpose.Aead()).failureOrNull() shouldBe KeysetFailure.Unavailable
        switchable.isFailing = false
        ledger.isFailing = true
        vault.load(NAME).failureOrNull() shouldBe KeysetFailure.Unavailable
        ledger.isFailing = false
        repository.isFailing = true
        vault.load(NAME).failureOrNull() shouldBe KeysetFailure.Unavailable
        vault.update(NAME) { keyset -> keyset }.failureOrNull() shouldBe KeysetFailure.Unavailable
        vault.create("other", KeyPurpose.Aead()).failureOrNull() shouldBe KeysetFailure.Unavailable
    }
})
