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

package com.davils.krypt.stream.fixture

import com.davils.krypt.core.SecretText
import com.davils.krypt.core.environment
import com.davils.krypt.core.policy.cryptoPolicy
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keyset
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.stream.Containers
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.manifest.Manifests
import kotlinx.io.bytestring.ByteString

internal const val ITERATIONS: Int = 1_000
internal const val SEGMENT: Int = 4_096
internal const val PASSWORD: String = "correct horse battery staple"

internal val crypto: Crypto = Crypto(
    environment {
        policy = cryptoPolicy {
            minimumIterations = ITERATIONS
            minimumVerifiedIterations = ITERATIONS
        }
    },
)

internal val keysets: Keysets = Keysets(crypto)

internal val containers: Containers = Containers(crypto)

internal val manifests: Manifests = Manifests(crypto)

internal fun password(): SecretText = SecretText.of(PASSWORD)

internal fun bytes(size: Int): ByteString = ByteString(ByteArray(size) { index -> (index * PRIME).toByte() })

internal fun utf8(text: String): ByteString = ByteString(text.encodeToByteArray())

internal fun flipped(bytes: ByteString, index: Int): ByteString {
    val array = bytes.toByteArray()
    array[index] = (array[index].toInt() xor 1).toByte()
    return ByteString(array)
}

internal fun limited(limits: StreamLimits): Containers = Containers(crypto = crypto, limits = limits)

internal suspend fun aeadKeyset(): Keyset = keysets.generate(KeyPurpose.Aead())

private const val PRIME: Int = 31
