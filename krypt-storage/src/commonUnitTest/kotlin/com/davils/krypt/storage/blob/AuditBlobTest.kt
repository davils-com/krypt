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

package com.davils.krypt.storage.blob

import com.davils.kore.core.outcome.failureOrNull
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.storage.StorageFailure
import com.davils.krypt.storage.fixture.MemoryBlobStore
import com.davils.krypt.storage.fixture.MemoryLedger
import com.davils.krypt.storage.fixture.SEGMENT
import com.davils.krypt.storage.fixture.blobStore
import com.davils.krypt.storage.fixture.bytes
import com.davils.krypt.storage.fixture.containers
import com.davils.krypt.storage.fixture.keysets
import com.davils.krypt.storage.fixture.utf8
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val NAME: String = "contracts/42.pdf"

class AuditBlobTest : FunSpec({
    test("an old version put back under the blinded key of the old names key is a rollback") {
        val store = MemoryBlobStore()
        val ledger = MemoryLedger()
        val dataKeys = keysets.aead(keysets.generate(KeyPurpose.Aead()))
        val names = keysets.generate(KeyPurpose.Mac())
        val before = EncryptedBlobStore(
            containers = containers,
            store = store,
            dataKeys = dataKeys,
            names = keysets.mac(names),
            ledger = ledger,
            segmentSize = SEGMENT,
        )
        before.put(NAME, utf8("version 1"))
        val oldKey = store.objects.keys.single()
        val versionOne = store.objects.getValue(oldKey)
        before.put(NAME, utf8("version 2"))
        val after = EncryptedBlobStore(
            containers = containers,
            store = store,
            dataKeys = dataKeys,
            names = keysets.mac(keysets.rotate(names)),
            ledger = ledger,
            segmentSize = SEGMENT,
        )
        after.rewrap(NAME).failureOrNull() shouldBe null
        val newKey = store.objects.keys.single()
        store.objects.remove(newKey)
        store.objects[oldKey] = versionOne
        after.get(NAME).failureOrNull() shouldBe StorageFailure.Rollback
    }

    test("an object deleted and put again cannot be swapped for the deleted object of the same version") {
        val store = MemoryBlobStore()
        val blobs = blobStore(store, MemoryLedger())
        blobs.put(NAME, utf8("signed by the old owner"))
        val key = store.objects.keys.single()
        val deleted = store.objects.getValue(key)
        blobs.delete(NAME)
        blobs.put(NAME, utf8("signed by the new owner"))
        store.objects[key] = deleted
        blobs.get(NAME).failureOrNull() shouldBe StorageFailure.Rollback
    }

    test("a put over a damaged object does not throw an internal refusal") {
        val store = MemoryBlobStore()
        val blobs = blobStore(store)
        blobs.put(NAME, bytes(10))
        val key = store.objects.keys.single()
        store.objects[key] = ByteString(ByteArray(64))
        shouldNotThrowAny { blobs.put(NAME, bytes(10)) }
    }

    test("a put after a rotation of the names key set works with a ledger") {
        val store = MemoryBlobStore()
        val ledger = MemoryLedger()
        val dataKeys = keysets.aead(keysets.generate(KeyPurpose.Aead()))
        val names = keysets.generate(KeyPurpose.Mac())
        val before = EncryptedBlobStore(
            containers = containers,
            store = store,
            dataKeys = dataKeys,
            names = keysets.mac(names),
            ledger = ledger,
            segmentSize = SEGMENT,
        )
        before.put(NAME, bytes(10))
        val after = EncryptedBlobStore(
            containers = containers,
            store = store,
            dataKeys = dataKeys,
            names = keysets.mac(keysets.rotate(names)),
            ledger = ledger,
            segmentSize = SEGMENT,
        )
        val metadata = shouldNotThrowAny { after.put(NAME, bytes(20)) }
        metadata.version shouldBe 2L
    }
})
