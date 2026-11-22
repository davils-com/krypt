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

import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseAlgorithmKind
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.internal.CoseException.Companion.present
import kotlinx.io.bytestring.ByteString

internal object Layers {
    fun encodingOf(headers: CoseHeaders): ByteString =
        Cbor.encode(headers.parameters).takeUnless { headers.isEmpty } ?: Bytes.Empty

    fun withAlgorithm(
        protectedHeaders: CoseHeaders,
        unprotectedHeaders: CoseHeaders,
        algorithm: CoseAlgorithm,
    ): CoseHeaders {
        val existing = protectedHeaders[HeaderLabels.ALGORITHM] ?: unprotectedHeaders[HeaderLabels.ALGORITHM]
        require(existing == null || existing.longOrNull() == algorithm.id) {
            "The algorithm of the headers is ${algorithm.algorithmName}"
        }
        val added = protectedHeaders.with(HeaderLabels.ALGORITHM, labelOf(algorithm.id))
        return protectedHeaders.takeIf { existing != null } ?: added
    }

    fun withKeyId(protectedHeaders: CoseHeaders, unprotectedHeaders: CoseHeaders, keyId: ByteString?): CoseHeaders {
        val isGiven = protectedHeaders.keyId != null || unprotectedHeaders.keyId != null
        val missing = keyId?.takeUnless { isGiven }
        val added = missing?.let { bytes -> unprotectedHeaders.with(HeaderLabels.KEY_ID, bytesOf(bytes)) }
        return added ?: unprotectedHeaders
    }

    fun requireDistinct(protectedHeaders: CoseHeaders, unprotectedHeaders: CoseHeaders) {
        require(isDistinct(protectedHeaders, unprotectedHeaders)) { "A header label is in one bucket only" }
        require(unprotectedHeaders.critical.isEmpty()) { "The crit header parameter is protected" }
    }

    fun isDistinct(protectedHeaders: CoseHeaders, unprotectedHeaders: CoseHeaders): Boolean =
        protectedHeaders.parameters.keys.all { label -> unprotectedHeaders[label] == null }

    fun algorithmOf(
        protectedHeaders: CoseHeaders,
        unprotectedHeaders: CoseHeaders,
        allowed: Set<CoseAlgorithm>,
        kind: CoseAlgorithmKind,
    ): CoseAlgorithm {
        val item = protectedHeaders[HeaderLabels.ALGORITHM] ?: unprotectedHeaders[HeaderLabels.ALGORITHM]
        val algorithm = item?.longOrNull()?.let { id -> CoseAlgorithm.of(id) }
        val permitted = algorithm?.takeIf { found -> found in allowed && found.kind == kind }
        return present(permitted, CoseFailure.AlgorithmNotPermitted)
    }

    fun checkCritical(protectedHeaders: CoseHeaders, understood: List<CborItem>) {
        protectedHeaders.critical.forEach { label ->
            ensure(protectedHeaders[label] != null, CoseFailure.Malformed)
            ensure(label in understood, CoseFailure.UnknownCritical)
        }
    }

    fun keyIdOf(protectedHeaders: CoseHeaders, unprotectedHeaders: CoseHeaders): ByteString? =
        protectedHeaders.keyId ?: unprotectedHeaders.keyId
}
