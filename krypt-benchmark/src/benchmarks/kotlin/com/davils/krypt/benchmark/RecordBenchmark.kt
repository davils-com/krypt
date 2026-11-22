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

import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.storage.record.BlindIndex
import com.davils.krypt.storage.record.RecordCipher
import com.davils.krypt.storage.record.RecordContext
import kotlinx.benchmark.Benchmark
import kotlinx.benchmark.Scope
import kotlinx.benchmark.Setup
import kotlinx.benchmark.State

@State(Scope.Benchmark)
class RecordBenchmark {
    private val crypto = Crypto()
    private val keysets = Keysets(crypto)
    private val context = RecordContext(table = "customers", column = COLUMN, row = "4711")
    private var cipher: RecordCipher? = null
    private var index: BlindIndex? = null
    private var ciphertext = ""

    @Setup
    fun prepare() {
        val aead = synchronously { keysets.generate(KeyPurpose.Aead()) }
        val mac = synchronously { keysets.generate(KeyPurpose.Mac()) }
        val records = RecordCipher(keysets.aead(aead))
        cipher = records
        index = BlindIndex(mac = keysets.mac(mac), column = COLUMN)
        ciphertext = synchronously { records.encryptText(value = FIELD, context = context) }
    }

    @Benchmark
    fun encryptField(): String = synchronously { records().encryptText(value = FIELD, context = context) }

    @Benchmark
    fun decryptField(): String = synchronously {
        val plaintext = records().decryptText(ciphertext = ciphertext, context = context)
        checkNotNull(plaintext) { "The field failed to decrypt" }
    }

    @Benchmark
    fun blindIndex(): String = synchronously {
        val blind = checkNotNull(index) { "The blind index is not prepared" }
        blind.of(FIELD)
    }

    private fun records(): RecordCipher = checkNotNull(cipher) { "The record cipher is not prepared" }

    private companion object {
        const val COLUMN: String = "email"
        const val FIELD: String = "jane.doe@example.com"
    }
}
