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
import com.davils.krypt.cose.CoseHeaders
import kotlinx.io.bytestring.ByteString

internal class Layer(
    val protectedHeaders: CoseHeaders,
    val unprotectedHeaders: CoseHeaders,
    val externalAad: ByteString,
    val isDetached: Boolean,
) {
    fun buckets(algorithm: CoseAlgorithm, keyId: ByteString?): Buckets {
        val withAlgorithm = Layers.withAlgorithm(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            algorithm = algorithm,
        )
        return bucketsOf(withAlgorithm = withAlgorithm, keyId = keyId)
    }

    fun body(): Buckets = bucketsOf(withAlgorithm = protectedHeaders, keyId = null)

    private fun bucketsOf(withAlgorithm: CoseHeaders, keyId: ByteString?): Buckets {
        val withKeyId = Layers.withKeyId(
            protectedHeaders = withAlgorithm,
            unprotectedHeaders = unprotectedHeaders,
            keyId = keyId,
        )
        Layers.requireDistinct(protectedHeaders = withAlgorithm, unprotectedHeaders = withKeyId)
        return Buckets(
            protectedHeaders = withAlgorithm,
            protectedEncoding = Layers.encodingOf(withAlgorithm),
            unprotectedHeaders = withKeyId,
        )
    }

    fun withUnprotected(headers: CoseHeaders): Layer = Layer(
        protectedHeaders = protectedHeaders,
        unprotectedHeaders = headers,
        externalAad = externalAad,
        isDetached = isDetached,
    )
}
