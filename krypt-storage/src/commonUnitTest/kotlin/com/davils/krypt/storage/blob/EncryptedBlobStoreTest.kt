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
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val NAME: String = "invoices/2026/42.pdf"
private const val OTHER: String = "invoices/2026/43.pdf"
private const val TYPE: String = "application/pdf"
private const val SIZE: Int = 3 * SEGMENT + 17
private const val OFFSET: Long = 4_000L
private const val LENGTH: Int = 200
private const val FUTURE: Long = 7L
private const val SEGMENTS: Int = 4
private const val TAG: Int = 16
private const val REMAINDER: Int = 5
private const val METADATA_BYTE: Int = 20
private const val HEAD: Int = 9
private const val LENGTH_BYTE: Int = 5
private const val HUGE: Byte = 0x7F
private const val FORMAT_BYTE: Int = 4
private const val LONG_TEXT: Int = 2_000
private const val TOO_MANY: Int = 33
private const val DEFAULT_SEGMENT: Int = 65_536
private const val CONTROL: String = "a\u0000b"

class EncryptedBlobStoreTest : FunSpec({
    test("objects are stored encrypted under blinded names and read back") {
        val store = MemoryBlobStore()
        val blobs = blobStore(store)
        val metadata = blobs.put(
            name = NAME,
            content = bytes(SIZE),
            contentType = TYPE,
            attributes = mapOf("b" to "2", "a" to "1"),
        )
        metadata.version shouldBe 1L
        metadata.attributes.keys.toList() shouldBe listOf("a", "b")
        store.objects.keys.single() shouldNotContain "invoices"
        val stored = store.objects.values.single()
        stored.toByteArray().decodeToString() shouldNotContain TYPE
        blobs.get(NAME).getOrNull() shouldBe bytes(SIZE)
        blobs.metadata(NAME).getOrNull() shouldBe metadata
        val sink = BufferSink(Int.MAX_VALUE)
        blobs.read(NAME, sink).getOrNull() shouldBe metadata
        sink.toByteString() shouldBe bytes(SIZE)
        val opened = checkNotNull(blobs.open(NAME).getOrNull())
        opened.metadata shouldBe metadata
        opened.reader.read(
            OFFSET,
            LENGTH,
        ) shouldBe bytes(SIZE).substring(startIndex = OFFSET.toInt(), endIndex = OFFSET.toInt() + LENGTH)
        opened.toString() shouldContain "ObjectMetadata"
        opened.close()
        blobs.put(NAME, bytes(1)).version shouldBe 2L
        blobs.get(NAME).getOrNull() shouldBe bytes(1)
        blobs.get(OTHER).failureOrNull() shouldBe StorageFailure.Missing
        blobs.toString() shouldContain "EncryptedBlobStore"
        blobs.delete(NAME) shouldBe true
        blobs.delete(NAME) shouldBe false
        blobs.metadata(NAME).failureOrNull() shouldBe StorageFailure.Missing
        shouldThrow<IllegalArgumentException> { blobs.get("") }
    }

    test("an object moved to another name is refused") {
        val store = MemoryBlobStore()
        val blobs = blobStore(store)
        blobs.put(NAME, bytes(SIZE))
        blobs.put(OTHER, bytes(1))
        val keys = store.objects.keys.toList()
        val first = store.objects.getValue(keys[0])
        store.objects[keys[0]] = store.objects.getValue(keys[1])
        store.objects[keys[1]] = first
        blobs.get(NAME).failureOrNull() shouldBe StorageFailure.DecryptionFailed
        blobs.open(OTHER).failureOrNull() shouldBe StorageFailure.DecryptionFailed
    }

    test("an old version put back is a rollback only with a ledger") {
        val store = MemoryBlobStore()
        val ledger = MemoryLedger()
        val blobs = blobStore(store, ledger)
        blobs.put(NAME, bytes(1))
        val key = store.objects.keys.single()
        val first = store.objects.getValue(key)
        blobs.put(NAME, bytes(2)).version shouldBe 2L
        store.objects[key] = first
        blobs.get(NAME).failureOrNull() shouldBe StorageFailure.Rollback
        ledger.versions[key] = 1L
        blobs.get(NAME).getOrNull() shouldBe bytes(1)
        ledger.versions[key] = FUTURE
        val racing = object : VersionLedger {
            override suspend fun current(key: String): Long? = null

            override suspend fun record(key: String, version: Long, expected: Long?): Boolean = false

            override suspend fun forget(key: String) = Unit
        }
        shouldThrow<IllegalStateException> { blobStoreWith(store, blobs, racing).put(NAME, bytes(1)) }
        blobs.delete(NAME) shouldBe true
        ledger.versions shouldBe mapOf(key to FUTURE + 1)
    }

    test("changed and foreign bytes are refused") {
        val store = MemoryBlobStore()
        val blobs = blobStore(store)
        blobs.put(NAME, bytes(SIZE))
        val key = store.objects.keys.single()
        val original = store.objects.getValue(key)
        val head = original.toByteArray().copyOf(HEAD)
        head[LENGTH_BYTE] = HUGE
        val oversized = ByteString(head)
        val cases = mapOf(
            utf8("junk") to StorageFailure.Malformed,
            flipped(original, 0) to StorageFailure.Malformed,
            flipped(original, FORMAT_BYTE) to StorageFailure.Malformed,
            oversized to StorageFailure.Malformed,
            flipped(original, METADATA_BYTE) to StorageFailure.DecryptionFailed,
            flipped(original, original.size - 1) to StorageFailure.DecryptionFailed,
            original.substring(startIndex = 0, endIndex = original.size - SEGMENT) to StorageFailure.DecryptionFailed,
        )
        cases.forEach { (bytes, failure) ->
            store.objects[key] = bytes
            blobs.get(NAME).failureOrNull() shouldBe failure
        }
        store.objects[key] = original.substring(
            startIndex = 0,
            endIndex = original.size - SIZE - SEGMENTS * TAG + REMAINDER,
        )
        blobs.open(NAME).failureOrNull() shouldBe StorageFailure.Malformed
    }

    test("objects survive rotations and move to the new keys") {
        val store = MemoryBlobStore()
        val dataKeys = keysets.generate(KeyPurpose.Aead())
        val names = keysets.generate(KeyPurpose.Mac())
        val ledger = MemoryLedger()
        val before = EncryptedBlobStore(
            containers = containers,
            store = store,
            dataKeys = keysets.aead(dataKeys),
            names = keysets.mac(names),
            ledger = ledger,
            segmentSize = SEGMENT,
        )
        before.put(NAME, bytes(SIZE))
        val oldKey = store.objects.keys.single()
        val after = EncryptedBlobStore(
            containers = containers,
            store = store,
            dataKeys = keysets.aead(keysets.rotate(dataKeys)),
            names = keysets.mac(keysets.rotate(names)),
            ledger = ledger,
        )
        after.get(NAME).getOrNull() shouldBe bytes(SIZE)
        after.rewrap(NAME).getOrNull()?.version shouldBe 1L
        store.objects.keys.single() shouldNotBe oldKey
        ledger.versions.keys shouldBe store.objects.keys
        after.get(NAME).getOrNull() shouldBe bytes(SIZE)
        after.rewrap(NAME).getOrNull()?.version shouldBe 1L
        after.rewrap(OTHER).failureOrNull() shouldBe StorageFailure.Missing
        val newKey = store.objects.keys.single()
        val moved = store.objects.getValue(newKey)
        store.objects[newKey] = flipped(moved, moved.size - 1)
        after.rewrap(NAME).failureOrNull() shouldBe StorageFailure.DecryptionFailed
        after.put(OTHER, bytes(1))
        after.segmentSize shouldBe DEFAULT_SEGMENT
    }

    test("metadata hides its texts and keeps its limits") {
        val metadata = ObjectMetadata(
            name = CONTROL,
            version = 1L,
            contentType = TYPE,
            createdAt = Instant.DISTANT_PAST,
        )
        metadata.toString() shouldNotContain "\u0000"
        metadata shouldBe ObjectMetadata(
            name = CONTROL,
            version = 1L,
            contentType = TYPE,
            createdAt = Instant.DISTANT_PAST,
        )
        metadata shouldNotBe ObjectMetadata(
            name = NAME,
            version = 1L,
            contentType = TYPE,
            createdAt = Instant.DISTANT_PAST,
        )
        metadata shouldNotBe Any()
        metadata.hashCode() shouldBe listOf(CONTROL, 1L).hashCode()
        shouldThrow<IllegalArgumentException> {
            ObjectMetadata(
                name = NAME,
                version = 1L,
                contentType = TYPE,
                createdAt = Instant.DISTANT_PAST,
                attributes = (1..TOO_MANY).associate { index -> "$index" to "" },
            )
        }
        shouldThrow<IllegalArgumentException> {
            ObjectMetadata(
                name = "x".repeat(LONG_TEXT),
                version = 1L,
                contentType = TYPE,
                createdAt = Instant.DISTANT_PAST,
            )
        }
    }
})

private fun flipped(bytes: ByteString, index: Int): ByteString {
    val array = bytes.toByteArray()
    array[index] = (array[index].toInt() xor 1).toByte()
    return ByteString(array)
}

private fun blobStoreWith(
    store: MemoryBlobStore,
    blobs: EncryptedBlobStore,
    ledger: VersionLedger,
): EncryptedBlobStore = EncryptedBlobStore(
    containers = containers,
    store = store,
    dataKeys = blobs.dataKeys,
    names = blobs.names,
    ledger = ledger,
    segmentSize = SEGMENT,
)
