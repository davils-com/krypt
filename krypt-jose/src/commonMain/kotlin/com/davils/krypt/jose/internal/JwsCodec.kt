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
import com.davils.krypt.jose.jws.JwsMessage
import com.davils.krypt.jose.jws.JwsSignature
import kotlinx.io.bytestring.ByteString

private const val COMPACT_PARTS: Int = 3
private const val PAYLOAD: String = "payload"
private const val SIGNATURES: String = "signatures"
private const val SIGNATURE: String = "signature"
private const val PROTECTED: String = "protected"
private const val HEADER: String = "header"

internal class JwsCodec(private val limits: JoseLimits) {
    private val headers = HeaderReader(limits)

    fun decode(text: String): Outcome<JwsMessage, JoseFailure> = decoding {
        refuseUnless(text.length <= limits.maximumBytes, JoseFailure.LimitExceeded)
        when (text.startsWith('{')) {
            true -> json(text)
            false -> compact(text)
        }
    }

    private fun compact(text: String): JwsMessage {
        val parts = text.split('.')
        require(parts.size == COMPACT_PARTS)
        val protected = headers.headerOf(parts[0])
        val signature = signatureOf(
            protected = protected,
            unprotected = JsonValue.Object.Empty,
            encoded = parts[0],
            bytes = requireNotNull(Base64Url.decode(parts[2])),
        )
        val isEncoded = isEncoded(protected)
        val payload = payloadOf(part = parts[1], isEncoded = isEncoded).takeIf { parts[1].isNotEmpty() }
        return JwsMessage(
            signatures = listOf(signature),
            payload = payload,
            isCompact = true,
            isPayloadEncoded = isEncoded,
            payloadPart = parts[1],
        )
    }

    private fun json(text: String): JwsMessage {
        val json = headers.objectOf(requireNotNull(utf8OrNull(text)))
        val entries = entriesOf(json)
        val signatures = entries.map { entry -> entryOf(entry) }
        val encodings = signatures.map { signature -> isEncoded(signature.protectedHeader) }
        require(encodings.distinct().size == 1)
        val isEncoded = encodings.first()
        val part = json.text(PAYLOAD)
        return JwsMessage(
            signatures = signatures,
            payload = part?.let { found -> payloadOf(part = found, isEncoded = isEncoded) },
            isCompact = false,
            isPayloadEncoded = isEncoded,
            payloadPart = part.orEmpty(),
        )
    }

    private fun entriesOf(json: JsonValue.Object): List<JsonValue.Object> {
        val list = json[SIGNATURES] ?: return listOf(json)
        require(list is JsonValue.Array && FLATTENED.none { name -> name in json })
        require(list.items.isNotEmpty())
        refuseUnless(list.items.size <= limits.maximumRecipients, JoseFailure.LimitExceeded)
        val entries = list.items.filterIsInstance<JsonValue.Object>()
        require(entries.size == list.items.size)
        return entries
    }

    private fun entryOf(entry: JsonValue.Object): JwsSignature {
        val encoded = entry.text(PROTECTED)
        val protected = encoded?.let { found -> headers.headerOf(found) } ?: JsonValue.Object.Empty
        require(encoded == null || protected.members.isNotEmpty())
        val unprotected = entry.member(HEADER) ?: JsonValue.Object.Empty
        HeaderRules.checkTypes(unprotected)
        require(HeaderNames.BASE64 !in unprotected)
        return signatureOf(
            protected = protected,
            unprotected = unprotected,
            encoded = encoded.orEmpty(),
            bytes = requireNotNull(entry.bytes(SIGNATURE)),
        )
    }

    private fun signatureOf(
        protected: JsonValue.Object,
        unprotected: JsonValue.Object,
        encoded: String,
        bytes: ByteString,
    ): JwsSignature {
        val signature = JwsSignature(
            protectedHeader = protected,
            unprotectedHeader = unprotected,
            signature = bytes,
            protectedEncoded = encoded,
        )
        signature.header.members.requiredText(HeaderNames.ALGORITHM)
        return signature
    }

    private fun payloadOf(part: String, isEncoded: Boolean): ByteString = when (isEncoded) {
        true -> requireNotNull(Base64Url.decode(part))
        false -> ByteString(requireNotNull(utf8OrNull(part)))
    }

    private fun isEncoded(protected: JsonValue.Object): Boolean {
        val isEncoded = protected.bool(HeaderNames.BASE64) != false
        val critical = protected.stringsOf(HeaderNames.CRITICAL).orEmpty()
        require(isEncoded || HeaderNames.BASE64 in critical)
        return isEncoded
    }

    private companion object {
        val FLATTENED: List<String> = listOf(SIGNATURE, PROTECTED, HEADER)
    }
}
