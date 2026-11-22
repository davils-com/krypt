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

package com.davils.krypt.benchmark

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.storage.blob.EncryptedBlobStore
import com.davils.krypt.storage.blob.ObjectMetadata
import com.davils.krypt.stream.Containers
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.io.bytestring.ByteString

@State(Scope.Benchmark)
class BlobStoreBenchmark {
    private val crypto = Crypto()
    private val keysets = Keysets(crypto)
    private val content = payload(MEBIBYTE)
    private var blobs: EncryptedBlobStore? = null

    @Setup
    fun prepare() {
        val dataKeys = synchronously { keysets.generate(KeyPurpose.Aead()) }
        val names = synchronously { keysets.generate(KeyPurpose.Mac()) }
        val store = EncryptedBlobStore(
            containers = Containers(crypto),
            store = MemoryBlobStore(),
            dataKeys = keysets.aead(dataKeys),
            names = keysets.mac(names),
            ledger = MemoryLedger(),
        )
        synchronously { store.put(name = READ_NAME, content = content) }
        blobs = store
    }

    @Benchmark
    fun put(): ObjectMetadata = synchronously { store().put(name = WRITE_NAME, content = content) }

    @Benchmark
    fun get(): ByteString = synchronously {
        val outcome = store().get(READ_NAME)
        checkNotNull(outcome.getOrNull()) { "The object failed to read" }
    }

    private fun store(): EncryptedBlobStore = checkNotNull(blobs) { "The blob store is not prepared" }

    private companion object {
        const val READ_NAME: String = "reports/read.bin"
        const val WRITE_NAME: String = "reports/write.bin"
    }
}
