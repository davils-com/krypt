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
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.storage.StorageFailure
import com.davils.krypt.storage.fixture.MemoryBlobStore
import com.davils.krypt.storage.fixture.blobStore
import com.davils.krypt.storage.fixture.bytes
import com.davils.krypt.storage.fixture.containers
import com.davils.krypt.storage.fixture.keysets
import com.davils.krypt.storage.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val NAME: String = "photos/1.jpg"
private const val LABEL: String = "krypt blob v1 "
private const val LONG_NAME: Int = 1_025
private const val SMALL: Int = 20
private val LENGTH_BYTES: ByteArray = byteArrayOf(0, 0, -1, -1)
private const val BIG_NUMBER_BYTES: Int = 16
private val MAGIC: ByteString = utf8("KBLB")

private fun framed(encrypted: ByteString): ByteString {
    val size = encrypted.size
    val length = ByteString(0, 0, (size shr Byte.SIZE_BITS).toByte(), size.toByte())
    return ByteString(MAGIC.toByteArray() + byteArrayOf(1) + length.toByteArray() + encrypted.toByteArray())
}

class BlobEdgeTest : FunSpec({
    test("names and subjects have bounded lengths and a source keeps the default type") {
        val blobs = blobStore(MemoryBlobStore())
        shouldThrow<IllegalArgumentException> { blobs.get("x".repeat(LONG_NAME)) }
        val metadata = blobs.put(name = NAME, source = bytes(1).asByteSource())
        metadata.contentType shouldBe "application/octet-stream"
        metadata.attributes shouldBe emptyMap()
    }

    test("objects move to new keys without a ledger") {
        val store = MemoryBlobStore()
        val dataKeys = keysets.generate(KeyPurpose.Aead())
        val names = keysets.generate(KeyPurpose.Mac())
        val before = EncryptedBlobStore(
            containers = containers,
            store = store,
            dataKeys = keysets.aead(dataKeys),
            names = keysets.mac(names),
        )
        before.put(NAME, bytes(1))
        val oldKey = store.objects.keys.single()
        val after = EncryptedBlobStore(
            containers = containers,
            store = store,
            dataKeys = keysets.aead(dataKeys),
            names = keysets.mac(keysets.rotate(names)),
        )
        after.rewrap(NAME).getOrNull()?.version shouldBe 1L
        store.objects.keys.single() shouldNotBe oldKey
        after.put(NAME, bytes(2)).version shouldBe 2L
    }

    test("metadata that does not fit its object or its format is malformed") {
        val store = MemoryBlobStore()
        val blobs = blobStore(store)
        blobs.put(NAME, bytes(1))
        val key = store.objects.keys.single()
        val original = store.objects.getValue(key)
        val head = original.toByteArray().copyOf(SMALL)
        LENGTH_BYTES.forEachIndexed { index, value -> head[MAGIC.size + 1 + index] = value }
        store.objects[key] = ByteString(head)
        blobs.get(NAME).failureOrNull() shouldBe StorageFailure.Malformed
        val context = utf8(LABEL + NAME)
        store.objects[key] = framed(blobs.dataKeys.encrypt(plaintext = utf8("junk"), associatedData = context))
        blobs.metadata(NAME).failureOrNull() shouldBe StorageFailure.Malformed
        val hugeNumber = Der.encode {
            sequence {
                integer(1L)
                utf8String(NAME)
                integer(DerInteger.ofMagnitude(ByteString(ByteArray(BIG_NUMBER_BYTES) { 1 })))
            }
        }
        store.objects[key] = framed(blobs.dataKeys.encrypt(plaintext = hugeNumber, associatedData = context))
        blobs.metadata(NAME).failureOrNull() shouldBe StorageFailure.Malformed
    }
})
