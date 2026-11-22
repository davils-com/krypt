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

package com.davils.krypt.stream.internal

import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.stream.StreamSuite
import kotlinx.io.bytestring.ByteString

private const val LAST: Byte = 1
private const val MORE: Byte = 0

internal class SegmentCipher(
    private val crypto: Crypto,
    private val suite: StreamSuite,
    private val key: SecretKey,
    private val prefix: ByteString,
) {
    val tagBytes: Int get() = suite.aead.tagBytes

    suspend fun seal(index: Long, isLast: Boolean, plaintext: ByteString): ByteString = crypto.aead.encrypt(
        key = key,
        nonce = nonce(index, isLast),
        plaintext = plaintext,
        associatedData = ByteString(),
        algorithm = suite.aead,
    )

    suspend fun open(index: Long, isLast: Boolean, ciphertext: ByteString): ByteString? = crypto.aead.decrypt(
        key = key,
        nonce = nonce(index, isLast),
        ciphertext = ciphertext,
        associatedData = ByteString(),
        algorithm = suite.aead,
    )

    private fun nonce(index: Long, isLast: Boolean): ByteString {
        val flag = listOf(MORE, LAST)[isLast.compareTo(false)]
        return Octets.concat(prefix, Octets.u32(index), ByteString(flag))
    }
}
