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

package com.davils.krypt.storage

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.keyset.KeysetFailure
import com.davils.krypt.keyset.kms.LocalKms
import com.davils.krypt.keyset.store.KeysetRepository
import com.davils.krypt.keyset.store.KeysetVault
import com.davils.krypt.keyset.store.StoredKeyset
import com.davils.krypt.storage.fixture.MemoryRepository
import com.davils.krypt.storage.fixture.crypto
import com.davils.krypt.storage.fixture.keysets
import com.davils.krypt.storage.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private const val ADA: String = "ada"
private const val LONG_SUBJECT: Int = 201
private const val SECRET: String = "medical record"

class SubjectKeysTest : FunSpec({
    test("data of a subject is shredded with its key set") {
        val repository = MemoryRepository()
        val vault = KeysetVault(
            keysets = keysets,
            repository = repository,
            kms = LocalKms(crypto, crypto.keys.generateSecret()),
        )
        val subjects = SubjectKeys(vault)
        val aead = checkNotNull(subjects.aead(ADA).getOrNull())
        val ciphertext = aead.encrypt(utf8(SECRET))
        checkNotNull(subjects.aead(ADA).getOrNull()).decrypt(ciphertext) shouldBe utf8(SECRET)
        checkNotNull(subjects.rotate(ADA).getOrNull()).keys.size shouldBe 2
        checkNotNull(subjects.aead(ADA).getOrNull()).decrypt(ciphertext) shouldBe utf8(SECRET)
        subjects.shred(ADA) shouldBe true
        subjects.shred(ADA) shouldBe false
        checkNotNull(subjects.aead(ADA).getOrNull()).decrypt(ciphertext) shouldBe null
        subjects.toString() shouldContain "SubjectKeys"
        shouldThrow<IllegalArgumentException> { subjects.aead("") }
        shouldThrow<IllegalArgumentException> { subjects.aead("x".repeat(LONG_SUBJECT)) }
    }

    test("a key set created at the same time by another process is loaded") {
        val repository = MemoryRepository()
        val kms = LocalKms(crypto, crypto.keys.generateSecret())
        SubjectKeys(KeysetVault(keysets = keysets, repository = repository, kms = kms)).aead(ADA)
        var isHidden = true
        val late = object : KeysetRepository by repository {
            override suspend fun load(name: String): StoredKeyset? {
                val found = repository.load(name).takeUnless { isHidden }
                isHidden = false
                return found
            }
        }
        val subjects = SubjectKeys(KeysetVault(keysets = keysets, repository = late, kms = kms))
        val direct = SubjectKeys(KeysetVault(keysets = keysets, repository = repository, kms = kms))
        val expected = checkNotNull(direct.aead(ADA).getOrNull())
        val actual = checkNotNull(subjects.aead(ADA).getOrNull())
        actual.keyset shouldBe expected.keyset
    }

    test("a key set that cannot be read is reported, not replaced") {
        val repository = MemoryRepository()
        val writer = KeysetVault(
            keysets = keysets,
            repository = repository,
            kms = LocalKms(crypto, crypto.keys.generateSecret()),
        )
        SubjectKeys(writer).aead(ADA)
        val reader = KeysetVault(
            keysets = keysets,
            repository = repository,
            kms = LocalKms(crypto, crypto.keys.generateSecret()),
        )
        val outcome = SubjectKeys(reader).aead(ADA)
        outcome.failureOrNull() shouldBe KeysetFailure.DecryptionFailed
        repository.stored.size shouldBe 1
    }
})
