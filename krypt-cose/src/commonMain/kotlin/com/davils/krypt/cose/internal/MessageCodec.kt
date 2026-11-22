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

package com.davils.krypt.cose.internal

import com.davils.krypt.cose.CoseEncrypt
import com.davils.krypt.cose.CoseEncrypt0
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.CoseLimits
import com.davils.krypt.cose.CoseMac
import com.davils.krypt.cose.CoseMac0
import com.davils.krypt.cose.CoseMessage
import com.davils.krypt.cose.CoseMessageType
import com.davils.krypt.cose.CoseRecipient
import com.davils.krypt.cose.CoseSign
import com.davils.krypt.cose.CoseSign1
import com.davils.krypt.cose.CoseSignature
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborMode
import com.davils.krypt.cose.cbor.CborSimple
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.internal.CoseException.Companion.present
import kotlinx.io.bytestring.ByteString

internal class MessageCodec(private val limits: CoseLimits, private val mode: CborMode) {
    fun item(encoded: ByteString): CborItem =
        present(CborReader.decodeOrNull(encoded, limits.cbor, mode), CoseFailure.Malformed)

    fun message(item: CborItem): CoseMessage {
        val tag = present(item.tagOrNull(), CoseFailure.Malformed)
        val type = CoseMessageType.entries.firstOrNull { candidate -> candidate.tag == tag.number }
        return message(item, present(type, CoseFailure.Malformed))
    }

    fun message(item: CborItem, type: CoseMessageType): CoseMessage = when (type) {
        CoseMessageType.Sign1 -> sign1(item)
        CoseMessageType.Sign -> sign(item)
        CoseMessageType.Mac0 -> mac0(item)
        CoseMessageType.Mac -> mac(item)
        CoseMessageType.Encrypt0 -> encrypt0(item)
        CoseMessageType.Encrypt -> encrypt(item)
    }

    private fun partsOf(item: CborItem, type: CoseMessageType): List<CborItem> {
        val tag = item.tagOrNull()
        ensure(tag == null || tag.number == type.tag, CoseFailure.Malformed)
        val content = listOfNotNull(tag?.content, item).first()
        val parts = present(content.itemsOrNull(), CoseFailure.Malformed)
        ensure(parts.size == SIZES.getValue(type), CoseFailure.Malformed)
        return parts
    }

    fun sign1(item: CborItem): CoseSign1 {
        val parts = partsOf(item, CoseMessageType.Sign1)
        val buckets = buckets(parts)
        return CoseSign1(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            payload = optionalBytes(parts[2]),
            signature = bytes(parts[THIRD]),
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    fun sign(item: CborItem): CoseSign {
        val parts = partsOf(item, CoseMessageType.Sign)
        val buckets = buckets(parts)
        val signatures = present(parts[THIRD].itemsOrNull(), CoseFailure.Malformed)
        ensure(signatures.size in 1..limits.maximumSignatures, CoseFailure.Malformed)
        return CoseSign(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            payload = optionalBytes(parts[2]),
            signatures = signatures.map { signature -> signature(signature) },
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    private fun signature(item: CborItem): CoseSignature {
        val parts = present(item.itemsOrNull()?.takeIf { found -> found.size == SIGNATURE_SIZE }, CoseFailure.Malformed)
        val buckets = buckets(parts)
        return CoseSignature(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            signature = bytes(parts[2]),
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    fun mac0(item: CborItem): CoseMac0 {
        val parts = partsOf(item, CoseMessageType.Mac0)
        val buckets = buckets(parts)
        return CoseMac0(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            payload = optionalBytes(parts[2]),
            tag = bytes(parts[THIRD]),
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    fun mac(item: CborItem): CoseMac {
        val parts = partsOf(item, CoseMessageType.Mac)
        val buckets = buckets(parts)
        return CoseMac(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            payload = optionalBytes(parts[2]),
            tag = bytes(parts[THIRD]),
            recipients = recipients(parts[FOURTH], Budget(limits.maximumRecipients), isRequired = true),
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    fun encrypt0(item: CborItem): CoseEncrypt0 {
        val parts = partsOf(item, CoseMessageType.Encrypt0)
        val buckets = buckets(parts)
        return CoseEncrypt0(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            ciphertext = optionalBytes(parts[2]),
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    fun encrypt(item: CborItem): CoseEncrypt {
        val parts = partsOf(item, CoseMessageType.Encrypt)
        val buckets = buckets(parts)
        return CoseEncrypt(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            ciphertext = optionalBytes(parts[2]),
            recipients = recipients(parts[THIRD], Budget(limits.maximumRecipients), isRequired = true),
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    private fun recipients(item: CborItem, budget: Budget, isRequired: Boolean): List<CoseRecipient> {
        val entries = present(item.itemsOrNull(), CoseFailure.Malformed)
        ensure(entries.isNotEmpty() || !isRequired, CoseFailure.Malformed)
        budget.spend(entries.size)
        return entries.map { entry -> recipient(entry, budget) }
    }

    private fun recipient(item: CborItem, budget: Budget): CoseRecipient {
        val parts = present(item.itemsOrNull(), CoseFailure.Malformed)
        ensure(parts.size == SIGNATURE_SIZE || parts.size == RECIPIENT_SIZE, CoseFailure.Malformed)
        val buckets = buckets(parts)
        val nested = parts.getOrNull(THIRD)?.let { found -> recipients(found, budget, isRequired = true) }
        return CoseRecipient(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            ciphertext = optionalBytes(parts[2]),
            recipients = nested.orEmpty(),
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    private fun buckets(parts: List<CborItem>): Buckets {
        val encoding = bytes(parts[0])
        val protectedMap = encoding.takeIf { bytes -> bytes.size > 0 }?.let { bytes -> mapOf(item(bytes)) }
        val protectedHeaders = headersOf(protectedMap ?: CborMap.Empty)
        val unprotectedHeaders = headersOf(mapOf(parts[1]))
        val isDistinct = Layers.isDistinct(protectedHeaders = protectedHeaders, unprotectedHeaders = unprotectedHeaders)
        ensure(isDistinct, CoseFailure.Malformed)
        ensure(unprotectedHeaders.critical.isEmpty(), CoseFailure.Malformed)
        val chain = protectedHeaders.certificateChain + unprotectedHeaders.certificateChain
        ensure(chain.size <= limits.maximumCertificates, CoseFailure.Malformed)
        return Buckets(
            protectedHeaders = protectedHeaders,
            protectedEncoding = Layers.encodingOf(protectedHeaders).takeIf { protectedHeaders.isEmpty } ?: encoding,
            unprotectedHeaders = unprotectedHeaders,
        )
    }

    private fun headersOf(map: CborMap): CoseHeaders = present(CoseHeaders.ofOrNull(map), CoseFailure.Malformed)

    private fun mapOf(item: CborItem): CborMap = present(item.mapOrNull(), CoseFailure.Malformed)

    private fun bytes(item: CborItem): ByteString = present(item.bytesOrNull(), CoseFailure.Malformed)

    private fun optionalBytes(item: CborItem): ByteString? {
        ensure(item.bytesOrNull() != null || item == CborSimple.Null, CoseFailure.Malformed)
        return item.bytesOrNull()
    }

    private class Budget(private var remaining: Int) {
        fun spend(count: Int) {
            remaining -= count
            ensure(remaining >= 0, CoseFailure.Malformed)
        }
    }

    private companion object {
        const val THIRD: Int = 3
        const val FOURTH: Int = 4
        const val SIGNATURE_SIZE: Int = 3
        const val RECIPIENT_SIZE: Int = 4
        val SIZES: Map<CoseMessageType, Int> = mapOf(
            CoseMessageType.Sign1 to 4,
            CoseMessageType.Sign to 4,
            CoseMessageType.Mac0 to 4,
            CoseMessageType.Mac to 5,
            CoseMessageType.Encrypt0 to 3,
            CoseMessageType.Encrypt to 4,
        )
    }
}
