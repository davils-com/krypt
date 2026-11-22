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

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.keyset.fixture.MemoryRepository
import com.davils.krypt.keyset.fixture.crypto
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.keyset.kms.LocalKms
import com.davils.krypt.keyset.store.KeysetVault
import com.davils.krypt.keyset.store.StoredKeyset
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.types.shouldBeInstanceOf

private const val NAME: String = "payments"

class AuditKeysetTest : FunSpec({
    test("a repository that puts back an old revision cannot bring a destroyed key back") {
        val kms = LocalKms(crypto, crypto.keys.generateSecret())
        val repository = MemoryRepository()
        val vault = KeysetVault(keysets = keysets, repository = repository, kms = kms)
        val created = (vault.create(NAME, KeyPurpose.Aead()) as Outcome.Success).value
        val compromised = created.primaryId
        val old = repository.stored.getValue(NAME)
        vault.update(NAME) { keyset -> keysets.destroy(keysets.rotate(keyset), compromised) }
        val current = repository.stored.getValue(NAME)
        repository.stored[NAME] = StoredKeyset(revision = current.revision, encrypted = old.encrypted)
        val loaded = vault.load(NAME)
        loaded.shouldBeInstanceOf<Outcome.Failure<KeysetFailure>>()
    }
})
