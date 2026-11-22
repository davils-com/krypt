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

package com.davils.krypt.jose.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.jwe.EncryptedKey
import com.davils.krypt.jose.jwe.JweMessage
import kotlinx.io.bytestring.ByteString

private const val COMPACT_PARTS: Int = 5
private const val IV_PART: Int = 2
private const val CIPHERTEXT_PART: Int = 3
private const val TAG_PART: Int = 4

internal class JweCodec(private val limits: JoseLimits) {
    private val headers = HeaderReader(limits)

    fun decode(text: String): Outcome<JweMessage, JoseFailure> = decoding {
        refuseUnless(text.length <= limits.maximumBytes, JoseFailure.LimitExceeded)
        val message = when (text.startsWith('{')) {
            true -> json(text)
            false -> compact(text)
        }
        message.recipients.forEach { recipient ->
            val header = merged(listOf(message.protectedHeader, message.sharedHeader, recipient.header))
            header.requiredText(HeaderNames.ALGORITHM)
            header.requiredText(HeaderNames.ENCRYPTION)
        }
        message
    }

    private fun compact(text: String): JweMessage {
        val parts = text.split('.')
        require(parts.size == COMPACT_PARTS)
        return JweMessage(
            protectedHeader = headers.headerOf(parts[0]),
            sharedHeader = JsonValue.Object.Empty,
            recipients = listOf(EncryptedKey(header = JsonValue.Object.Empty, encryptedKey = bytesOf(parts[1]))),
            iv = bytesOf(parts[IV_PART]),
            ciphertext = bytesOf(parts[CIPHERTEXT_PART]),
            tag = bytesOf(parts[TAG_PART]),
            additionalData = null,
            isCompact = true,
            protectedEncoded = parts[0],
            additionalEncoded = null,
        )
    }

    private fun json(text: String): JweMessage {
        val json = headers.objectOf(text)
        val encoded = json.text(PROTECTED)
        val protected = encoded?.let { found -> headers.headerOf(found) } ?: JsonValue.Object.Empty
        require(encoded == null || protected.members.isNotEmpty())
        val shared = headerOf(json, SHARED)
        val additionalEncoded = json.text(ADDITIONAL_DATA)
        return JweMessage(
            protectedHeader = protected,
            sharedHeader = shared,
            recipients = recipientsOf(json),
            iv = requireNotNull(json.bytes(IV)),
            ciphertext = requireNotNull(json.bytes(CIPHERTEXT)),
            tag = requireNotNull(json.bytes(TAG)),
            additionalData = additionalEncoded?.let { found -> bytesOf(found) },
            isCompact = false,
            protectedEncoded = encoded.orEmpty(),
            additionalEncoded = additionalEncoded,
        )
    }

    private fun recipientsOf(json: JsonValue.Object): List<EncryptedKey> {
        val list = json[RECIPIENTS] ?: return listOf(recipientOf(json))
        require(list is JsonValue.Array && FLATTENED.none { name -> name in json })
        require(list.items.isNotEmpty())
        refuseUnless(list.items.size <= limits.maximumRecipients, JoseFailure.LimitExceeded)
        return list.items.map { item ->
            require(item is JsonValue.Object)
            recipientOf(item)
        }
    }

    private fun recipientOf(json: JsonValue.Object): EncryptedKey = EncryptedKey(
        header = headerOf(json, HEADER),
        encryptedKey = json.bytes(ENCRYPTED_KEY) ?: ByteString(),
    )

    private fun headerOf(json: JsonValue.Object, name: String): JsonValue.Object {
        val header = json.member(name) ?: JsonValue.Object.Empty
        HeaderRules.checkTypes(header)
        return header
    }

    private fun bytesOf(text: String): ByteString = requireNotNull(Base64Url.decode(text))

    private companion object {
        const val PROTECTED: String = "protected"
        const val SHARED: String = "unprotected"
        const val HEADER: String = "header"
        const val RECIPIENTS: String = "recipients"
        const val ENCRYPTED_KEY: String = "encrypted_key"
        const val ADDITIONAL_DATA: String = "aad"
        const val IV: String = "iv"
        const val CIPHERTEXT: String = "ciphertext"
        const val TAG: String = "tag"
        val FLATTENED: List<String> = listOf(HEADER, ENCRYPTED_KEY)
    }
}
