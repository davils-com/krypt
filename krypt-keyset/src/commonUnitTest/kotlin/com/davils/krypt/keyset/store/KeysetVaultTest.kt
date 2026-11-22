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

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.KeysetFailure
import com.davils.krypt.keyset.fixture.MemoryRepository
import com.davils.krypt.keyset.fixture.crypto
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.keyset.kms.LocalKms
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import kotlinx.io.bytestring.ByteString

private const val NAME: String = "payments"
private const val OTHER: String = "ledger"
private const val ATTEMPTS: Int = 3
private const val TOO_MANY: Int = 17

class KeysetVaultTest : FunSpec({
    val kms = LocalKms(crypto, crypto.keys.generateSecret())

    test("a vault creates, loads and rotates a named key set") {
        val repository = MemoryRepository()
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms)
        val created = checkNotNull(vault.create(NAME, KeyPurpose.Aead()).getOrNull())
        vault.load(NAME).getOrNull() shouldBe created
        vault.create(NAME, KeyPurpose.Aead()).failureOrNull() shouldBe KeysetFailure.Conflict
        val rotated = checkNotNull(vault.update(NAME) { keyset -> keysets.rotate(keyset) }.getOrNull())
        rotated.primaryId shouldNotBe created.primaryId
        repository.stored.getValue(NAME).revision shouldBe 2L
        vault.load(NAME).getOrNull() shouldBe rotated
        vault.load(OTHER).failureOrNull() shouldBe KeysetFailure.Missing
        vault.update(OTHER) { keyset -> keyset }.failureOrNull() shouldBe KeysetFailure.Missing
        vault.attempts shouldBe ATTEMPTS
        vault.delete(NAME) shouldBe true
        vault.delete(NAME) shouldBe false
        vault.load(NAME).failureOrNull() shouldBe KeysetFailure.Missing
        vault.toString() shouldContain "LocalKms"
    }

    test("a key set copied under another name is refused") {
        val repository = MemoryRepository()
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms)
        vault.create(NAME, KeyPurpose.Mac())
        repository.stored[OTHER] = repository.stored.getValue(NAME)
        vault.load(OTHER).failureOrNull() shouldBe KeysetFailure.DecryptionFailed
        vault.update(OTHER) { keyset -> keyset }.failureOrNull() shouldBe KeysetFailure.DecryptionFailed
    }

    test("an update tries again when another process changed the key set in between") {
        val repository = MemoryRepository()
        KeysetVault(keysets = keysets, repository = repository, kms = kms).create(NAME, KeyPurpose.Aead())
        val interfered = MemoryRepository(interferences = 2).also { it.stored.putAll(repository.stored) }
        val vault = KeysetVault(keysets = keysets, repository = interfered, kms = kms)
        val updated = vault.update(NAME) { keyset -> keysets.rotate(keyset) }
        checkNotNull(updated.getOrNull()).keys.size shouldBe 2
        val stubborn = MemoryRepository(interferences = ATTEMPTS).also { it.stored.putAll(repository.stored) }
        val giving = KeysetVault(keysets = keysets, repository = stubborn, kms = kms)
        giving.update(NAME) { keyset -> keysets.rotate(keyset) }.failureOrNull() shouldBe KeysetFailure.Conflict
    }

    test("names and attempts are checked") {
        val vault = KeysetVault(keysets = keysets, repository = MemoryRepository(), kms = kms)
        shouldThrow<IllegalArgumentException> { vault.load("") }
        shouldThrow<IllegalArgumentException> { vault.load("tab\there") }
        shouldThrow<IllegalArgumentException> { vault.load("delete\u007f") }
        shouldThrow<IllegalArgumentException> { vault.load("x".repeat(TOO_MANY * TOO_MANY)) }
        shouldThrow<IllegalArgumentException> {
            KeysetVault(keysets = keysets, repository = MemoryRepository(), kms = kms, attempts = 0)
        }
        shouldThrow<IllegalArgumentException> {
            KeysetVault(keysets = keysets, repository = MemoryRepository(), kms = kms, attempts = TOO_MANY)
        }
    }

    test("a stored key set has a positive revision and hides its bytes") {
        val stored = StoredKeyset(revision = 1L, encrypted = ByteString(1, 2))
        stored shouldBe StoredKeyset(revision = 1L, encrypted = ByteString(1, 2))
        stored shouldNotBe StoredKeyset(revision = 2L, encrypted = ByteString(1, 2))
        stored shouldNotBe StoredKeyset(revision = 1L, encrypted = ByteString(1))
        stored.hashCode() shouldBe 1L.hashCode()
        stored.toString() shouldBe "StoredKeyset(revision=1, bytes=2)"
        shouldThrow<IllegalArgumentException> { StoredKeyset(revision = 0L, encrypted = ByteString()) }
    }
})
