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
import com.davils.krypt.core.io.BufferSink
import com.davils.krypt.core.io.asByteSource
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.stream.ContainerSeal
import com.davils.krypt.stream.Containers
import com.davils.krypt.stream.Credential
import com.davils.krypt.stream.Recipient
import com.davils.krypt.stream.StreamSuite
import com.davils.krypt.stream.asRandomAccessSource
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Param
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.io.bytestring.ByteString

@State(Scope.Benchmark)
class ContainerBenchmark {
    @Param("1048576", "67108864")
    var size: Int = 0

    @Param("Aes256Gcm", "ChaCha20Poly1305")
    var suite: String = ""

    private val crypto = Crypto()
    private val keysets = Keysets(crypto)
    private val containers = Containers(crypto)
    private var streamSuite = StreamSuite.Aes256Gcm
    private var plaintext = ByteString()
    private var container = ByteString()
    private var recipients: List<Recipient> = emptyList()
    private var credentials: List<Credential> = emptyList()

    @Setup
    fun prepare() {
        streamSuite = StreamSuite.valueOf(suite)
        val keyset = synchronously { keysets.generate(KeyPurpose.Aead()) }
        val aead = keysets.aead(keyset)
        recipients = listOf(Recipient.Key(aead))
        credentials = listOf(Credential.Key(aead))
        plaintext = payload(size)
        val sink = BufferSink(Int.MAX_VALUE)
        synchronously {
            containers.encrypt(
                source = plaintext.asByteSource(),
                sink = sink,
                recipients = recipients,
                suite = streamSuite,
            )
        }
        container = sink.toByteString()
        val decrypted = decrypt()
        check(decrypted.plaintextBytes == size.toLong()) { "The container does not decrypt to its plaintext" }
    }

    @Benchmark
    fun encrypt(): ContainerSeal = synchronously {
        containers.encrypt(
            source = plaintext.asByteSource(),
            sink = DiscardingSink(),
            recipients = recipients,
            suite = streamSuite,
        )
    }

    @Benchmark
    fun decrypt(): ContainerSeal = synchronously {
        val outcome = containers.decrypt(
            source = container.asByteSource(),
            sink = DiscardingSink(),
            credentials = credentials,
        )
        checkNotNull(outcome.getOrNull()) { "The container failed to decrypt" }
    }

    @Benchmark
    fun openAndReadSegment(): ByteString = synchronously {
        val outcome = containers.open(source = container.asRandomAccessSource(), credentials = credentials)
        val reader = checkNotNull(outcome.getOrNull()) { "The container failed to open" }
        try {
            val segment = reader.segment(reader.segments / 2)
            checkNotNull(segment) { "A segment of the container failed to decrypt" }
        } finally {
            reader.close()
        }
    }
}
