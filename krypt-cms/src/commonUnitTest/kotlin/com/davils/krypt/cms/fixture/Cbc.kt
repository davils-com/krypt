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

package com.davils.krypt.cms.fixture

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.cms.Cms
import com.davils.krypt.cms.CmsFailure
import com.davils.krypt.cms.enveloped.ContentEncryption
import com.davils.krypt.cms.enveloped.Credential
import com.davils.krypt.cms.enveloped.EncryptedData
import com.davils.krypt.cms.enveloped.EnvelopedData
import com.davils.krypt.cms.enveloped.Recipient
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

internal suspend fun Cms.envelopCbc(
    content: ByteString,
    recipients: List<Recipient>,
    encryption: ContentEncryption,
): EnvelopedData = envelop(
    content = content,
    recipients = recipients,
    encryption = encryption,
    isUnauthenticatedCbcAllowed = true,
)

internal suspend fun Cms.encryptCbc(
    content: ByteString,
    key: SecretKey,
    encryption: ContentEncryption = ContentEncryption.Aes256Cbc,
): EncryptedData = encrypt(content = content, key = key, encryption = encryption, isUnauthenticatedCbcAllowed = true)

internal suspend fun Cms.decryptCbc(data: EnvelopedData, credential: Credential): Outcome<ByteString, CmsFailure> =
    decrypt(envelopedData = data, credential = credential, isUnauthenticatedCbcAllowed = true)

internal suspend fun Cms.decryptCbc(data: EncryptedData, key: SecretKey): Outcome<ByteString, CmsFailure> =
    decrypt(encryptedData = data, key = key, isUnauthenticatedCbcAllowed = true)
