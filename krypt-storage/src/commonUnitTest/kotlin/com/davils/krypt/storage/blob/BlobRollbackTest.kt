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
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keyset
import com.davils.krypt.keyset.KeysetAead
import com.davils.krypt.storage.StorageFailure
import com.davils.krypt.storage.fixture.MemoryBlobStore
import com.davils.krypt.storage.fixture.MemoryLedger
import com.davils.krypt.storage.fixture.SEGMENT
import com.davils.krypt.storage.fixture.blobStore
import com.davils.krypt.storage.fixture.bytes
import com.davils.krypt.storage.fixture.containers
import com.davils.krypt.storage.fixture.keysets
import com.davils.krypt.storage.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val NAME: String = "contracts/42.pdf"
private const val SIZE: Int = 10
private const val THIRD: Long = 3L

private fun blobs(
    store: MemoryBlobStore,
    ledger: MemoryLedger?,
    dataKeys: KeysetAead,
    names: Keyset,
): EncryptedBlobStore = EncryptedBlobStore(
    containers = containers,
    store = store,
    dataKeys = dataKeys,
    names = keysets.mac(names),
    ledger = ledger,
    segmentSize = SEGMENT,
)

class BlobRollbackTest : FunSpec({
    test("an old version put back under the blinded key of the old names key is a rollback") {
        val store = MemoryBlobStore()
        val ledger = MemoryLedger()
        val dataKeys = keysets.aead(keysets.generate(KeyPurpose.Aead()))
        val names = keysets.generate(KeyPurpose.Mac())
        val before = blobs(store = store, ledger = ledger, dataKeys = dataKeys, names = names)
        before.put(NAME, utf8("version 1"))
        val oldKey = store.objects.keys.single()
        val versionOne = store.objects.getValue(oldKey)
        before.put(NAME, utf8("version 2"))
        val after = blobs(store = store, ledger = ledger, dataKeys = dataKeys, names = keysets.rotate(names))
        after.rewrap(NAME).failureOrNull() shouldBe null
        val newKey = store.objects.keys.single()
        ledger.versions shouldBe mapOf(newKey to 2L)
        store.objects.remove(newKey)
        store.objects[oldKey] = versionOne
        after.get(NAME).failureOrNull() shouldBe StorageFailure.Rollback
        after.metadata(NAME).failureOrNull() shouldBe StorageFailure.Rollback
    }

    test("an object deleted and put again cannot be swapped for the deleted object of the same version") {
        val store = MemoryBlobStore()
        val ledger = MemoryLedger()
        val blobs = blobStore(store, ledger)
        blobs.put(NAME, utf8("signed by the old owner"))
        val key = store.objects.keys.single()
        val deleted = store.objects.getValue(key)
        blobs.delete(NAME) shouldBe true
        ledger.versions[key] shouldBe 2L
        blobs.get(NAME).failureOrNull() shouldBe StorageFailure.Missing
        store.objects[key] = deleted
        blobs.get(NAME).failureOrNull() shouldBe StorageFailure.Rollback
        blobs.put(NAME, utf8("signed by the new owner")).version shouldBe THIRD
        store.objects[key] = deleted
        blobs.get(NAME).failureOrNull() shouldBe StorageFailure.Rollback
    }

    test("an object the ledger has no record of is a rollback until it is put again") {
        val store = MemoryBlobStore()
        val dataKeys = keysets.aead(keysets.generate(KeyPurpose.Aead()))
        val names = keysets.generate(KeyPurpose.Mac())
        blobs(store = store, ledger = null, dataKeys = dataKeys, names = names).put(NAME, bytes(SIZE))
        val ledger = MemoryLedger()
        val guarded = blobs(store = store, ledger = ledger, dataKeys = dataKeys, names = names)
        guarded.get(NAME).failureOrNull() shouldBe StorageFailure.Rollback
        guarded.put(NAME, bytes(SIZE)).version shouldBe 2L
        guarded.get(NAME).getOrNull() shouldBe bytes(SIZE)
        guarded.delete("unknown") shouldBe false
        ledger.versions.values.toSet() shouldBe setOf(1L, 2L)
        ledger.versions.clear()
        guarded.delete(NAME) shouldBe true
        ledger.versions.values.single() shouldBe THIRD
    }

    test("a put over a damaged object starts a new version instead of throwing") {
        val store = MemoryBlobStore()
        val blobs = blobStore(store)
        blobs.put(NAME, bytes(SIZE))
        val key = store.objects.keys.single()
        store.objects[key] = ByteString(ByteArray(SIZE))
        blobs.put(NAME, bytes(SIZE)).version shouldBe 1L
        store.objects[key] = ByteString(ByteArray(SIZE))
        blobs.delete(NAME) shouldBe true
    }

    test("a put after a rotation of the names key set continues the version with a ledger") {
        val store = MemoryBlobStore()
        val ledger = MemoryLedger()
        val dataKeys = keysets.aead(keysets.generate(KeyPurpose.Aead()))
        val names = keysets.generate(KeyPurpose.Mac())
        blobs(store = store, ledger = ledger, dataKeys = dataKeys, names = names).put(NAME, bytes(SIZE))
        val after = blobs(store = store, ledger = ledger, dataKeys = dataKeys, names = keysets.rotate(names))
        after.put(NAME, bytes(SIZE)).version shouldBe 2L
        val key = store.objects.keys.single()
        ledger.versions shouldBe mapOf(key to 2L)
        after.get(NAME).getOrNull() shouldBe bytes(SIZE)
    }

    test("what the store and the ledger throw becomes unavailable when reading") {
        val store = MemoryBlobStore()
        val ledger = MemoryLedger()
        val blobs = blobStore(store, ledger)
        blobs.put(NAME, bytes(SIZE))
        ledger.isFailing = true
        blobs.get(NAME).failureOrNull() shouldBe StorageFailure.Unavailable
        shouldThrow<IllegalStateException> { blobs.delete(NAME) }
        store.objects.size shouldBe 1
        ledger.isFailing = false
        store.isFailing = true
        blobs.metadata(NAME).failureOrNull() shouldBe StorageFailure.Unavailable
        blobs.read(NAME, BufferSink(Int.MAX_VALUE)).failureOrNull() shouldBe StorageFailure.Unavailable
        blobs.open(NAME).failureOrNull() shouldBe StorageFailure.Unavailable
        blobs.rewrap(NAME).failureOrNull() shouldBe StorageFailure.Unavailable
    }

    test("a rewrap whose version cannot be carried to the new blinded key is unavailable and keeps the object") {
        val store = MemoryBlobStore()
        val ledger = MemoryLedger()
        val dataKeys = keysets.aead(keysets.generate(KeyPurpose.Aead()))
        val names = keysets.generate(KeyPurpose.Mac())
        blobs(store = store, ledger = ledger, dataKeys = dataKeys, names = names).put(NAME, bytes(SIZE))
        val oldKey = store.objects.keys.single()
        val after = blobs(store = store, ledger = ledger, dataKeys = dataKeys, names = keysets.rotate(names))
        ledger.isRefusing = true
        after.rewrap(NAME).failureOrNull() shouldBe StorageFailure.Unavailable
        shouldThrow<IllegalStateException> { after.delete(NAME) }
        store.objects.keys shouldBe setOf(oldKey)
        ledger.isRefusing = false
        after.get(NAME).getOrNull() shouldBe bytes(SIZE)
    }
})
