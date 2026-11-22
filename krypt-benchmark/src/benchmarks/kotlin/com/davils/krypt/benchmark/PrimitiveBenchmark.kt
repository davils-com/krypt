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

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.DigestAlgorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.cipher.SealedBox
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State
import kotlinx.benchmark.TearDown
import kotlinx.io.bytestring.ByteString

@State(Scope.Benchmark)
class PrimitiveBenchmark {
    private val crypto = Crypto()
    private val sealed = payload(SEALED_BYTES)
    private val digested = payload(MEBIBYTE)
    private var key: SecretKey? = null
    private var box: SealedBox? = null

    @Setup
    fun prepare() {
        val secret = crypto.keys.generateSecret(size = AeadAlgorithm.Aes256Gcm.keyBytes)
        key = secret
        box = synchronously { crypto.aead.seal(key = secret, plaintext = sealed) }
    }

    @TearDown
    fun destroy() {
        key?.destroy()
    }

    @Benchmark
    fun aesGcmSeal(): SealedBox = synchronously { crypto.aead.seal(key = secret(), plaintext = sealed) }

    @Benchmark
    fun aesGcmOpen(): ByteString = synchronously {
        val opened = crypto.aead.open(key = secret(), box = checkNotNull(box) { "No box is sealed" })
        checkNotNull(opened) { "The box failed to open" }
    }

    @Benchmark
    fun sha256(): ByteString = synchronously {
        crypto.digests.digest(data = digested, algorithm = DigestAlgorithm.Sha256)
    }

    private fun secret(): SecretKey = checkNotNull(key) { "No key is prepared" }

    private companion object {
        const val SEALED_BYTES: Int = 64 * KIBIBYTE
    }
}
