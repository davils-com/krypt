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

package com.davils.krypt.storage.fixture

import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.Keysets
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.storage.blob.EncryptedBlobStore
import com.davils.krypt.storage.blob.VersionLedger
import com.davils.krypt.stream.Containers
import kotlinx.io.bytestring.ByteString

internal const val SEGMENT: Int = 4_096

internal val crypto: Crypto = Crypto()

internal val keysets: Keysets = Keysets(crypto)

internal val containers: Containers = Containers(crypto)

internal fun bytes(size: Int): ByteString = ByteString(ByteArray(size) { index -> (index * PRIME).toByte() })

internal fun utf8(text: String): ByteString = ByteString(text.encodeToByteArray())

internal suspend fun blobStore(store: MemoryBlobStore, ledger: VersionLedger? = null): EncryptedBlobStore =
    EncryptedBlobStore(
        containers = containers,
        store = store,
        dataKeys = keysets.aead(keysets.generate(KeyPurpose.Aead())),
        names = keysets.mac(keysets.generate(KeyPurpose.Mac())),
        ledger = ledger,
        segmentSize = SEGMENT,
    )

private const val PRIME: Int = 31
