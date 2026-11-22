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

import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborSimple

internal object HeaderRules {
    private const val HASH_PARTS: Int = 2

    private val RULES: Map<Long, (CborItem) -> Boolean> = mapOf(
        HeaderLabels.ALGORITHM to { value -> isLabel(value) },
        HeaderLabels.CRITICAL to { value -> isCritical(value) },
        HeaderLabels.CONTENT_TYPE to { value -> isContentType(value) },
        HeaderLabels.KEY_ID to { value -> value.bytesOrNull() != null },
        HeaderLabels.IV to { value -> value.bytesOrNull() != null },
        HeaderLabels.PARTIAL_IV to { value -> value.bytesOrNull() != null },
        HeaderLabels.CERTIFICATE_CHAIN to { value -> isCertificateChain(value) },
        HeaderLabels.CERTIFICATE_HASH to { value -> isCertificateHash(value) },
        HeaderLabels.EPHEMERAL_KEY to { value -> value.mapOrNull() != null },
        HeaderLabels.SALT to { value -> value.bytesOrNull() != null },
        HeaderLabels.PARTY_U_IDENTITY to { value -> isBytesOrNull(value) },
        HeaderLabels.PARTY_U_NONCE to { value -> isNonce(value) },
        HeaderLabels.PARTY_U_OTHER to { value -> isBytesOrNull(value) },
        HeaderLabels.PARTY_V_IDENTITY to { value -> isBytesOrNull(value) },
        HeaderLabels.PARTY_V_NONCE to { value -> isNonce(value) },
        HeaderLabels.PARTY_V_OTHER to { value -> isBytesOrNull(value) },
    )

    fun isValid(parameters: CborMap): Boolean {
        val isTyped = parameters.entries.all { (label, value) -> isValid(label = label, value = value) }
        val hasBothIvs = HeaderLabels.IV in parameters && HeaderLabels.PARTIAL_IV in parameters
        return isTyped && !hasBothIvs
    }

    fun isLabel(item: CborItem): Boolean = item.integerOrNull()?.toLongOrNull() != null || item.textOrNull() != null

    private operator fun CborMap.contains(label: Long): Boolean = get(label) != null

    private fun isValid(label: CborItem, value: CborItem): Boolean {
        val rule = label.longOrNull()?.let { number -> RULES[number] } ?: { true }
        return isLabel(label) && rule(value)
    }

    private fun isCritical(value: CborItem): Boolean {
        val labels = value.itemsOrNull().orEmpty()
        return labels.isNotEmpty() && labels.all { label -> isLabel(label) }
    }

    private fun isContentType(value: CborItem): Boolean {
        val isUnsigned = value.integerOrNull()?.isNegative == false
        return isUnsigned || value.textOrNull() != null
    }

    private fun isCertificateChain(value: CborItem): Boolean {
        val certificates = value.itemsOrNull().orEmpty()
        val isArray = certificates.isNotEmpty() && certificates.all { item -> item.bytesOrNull() != null }
        return value.bytesOrNull() != null || isArray
    }

    private fun isCertificateHash(value: CborItem): Boolean {
        val parts = value.itemsOrNull()?.takeIf { found -> found.size == HASH_PARTS } ?: return false
        return isLabel(parts[0]) && parts[1].bytesOrNull() != null
    }

    private fun isBytesOrNull(value: CborItem): Boolean = value.bytesOrNull() != null || value == CborSimple.Null

    private fun isNonce(value: CborItem): Boolean = isBytesOrNull(value) || value.integerOrNull() != null
}
