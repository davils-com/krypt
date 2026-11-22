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

import com.davils.krypt.core.SecretBytes
import com.davils.krypt.keyset.kms.KeyManagementService
import com.davils.krypt.keyset.kms.LocalKms
import kotlinx.io.bytestring.ByteString

internal class MemoryKms(override val keyUri: String) : KeyManagementService {
    private val local = LocalKms(crypto = crypto, key = crypto.keys.generateSecret(), keyUri = keyUri)

    override suspend fun encrypt(plaintext: SecretBytes, associatedData: ByteString): ByteString =
        local.encrypt(plaintext = plaintext, associatedData = associatedData)

    override suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString): SecretBytes? =
        local.decrypt(ciphertext = ciphertext, associatedData = associatedData)
}
