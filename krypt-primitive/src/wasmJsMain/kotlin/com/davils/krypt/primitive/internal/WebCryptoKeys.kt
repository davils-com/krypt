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

@file:OptIn(ExperimentalWasmJsInterop::class)

package com.davils.krypt.primitive.internal

import com.davils.krypt.primitive.UnsupportedAlgorithmException
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey

internal object WebCryptoKeys {
    suspend fun secret(key: SecretKey, import: KeyImport): JsAny {
        val cache = cacheOf(key.handle)
        key.handle = cache
        val cached = cache[import.name]
        if (cached != null) return cached
        val imported = key.reveal { bytes ->
            JsBytes.withJs(
                bytes,
            ) { raw -> importOf(format = "raw", data = raw, import = import) }
        }
        cache[import.name] = imported
        return imported
    }

    suspend fun private(key: PrivateKey, import: KeyImport): JsAny {
        key.checkAlive()
        val cache = cacheOf(key.handle)
        key.handle = cache
        val cached = cache[import.name]
        if (cached != null) return cached
        val encoding = checkNotNull(key.encodingOrNull()) { "The private key has no encoding" }
        val imported = encoding.reveal { bytes ->
            JsBytes.withJs(
                bytes,
            ) { raw -> importRaw(format = "pkcs8", data = raw, import = import) }
        }
        cache[import.name] = imported
        return imported
    }

    suspend fun public(key: PublicKey, import: KeyImport): JsAny {
        val cache = cacheOf(key.handle)
        key.handle = cache
        val cached = cache[import.name]
        if (cached != null) return cached
        val imported = JsBytes.withJs(
            key.encoded.toByteArray(),
        ) { raw -> importRaw(format = "spki", data = raw, import = import) }
        cache[import.name] = imported
        return imported
    }

    private suspend fun importRaw(format: String, data: JsAny, import: KeyImport): JsAny =
        importKey(f = format, d = data, a = import.algorithm, e = false, u = usages(import.usages)).settled()

    private suspend fun importOf(format: String, data: JsAny, import: KeyImport): JsAny = try {
        importRaw(format = format, data = data, import = import)
    } catch (refused: WebCryptoRejection) {
        throw UnsupportedAlgorithmException(import.name, refused)
    }

    @Suppress("UNCHECKED_CAST")
    private fun cacheOf(handle: Any?): MutableMap<String, JsAny> =
        handle as? MutableMap<String, JsAny> ?: mutableMapOf()
}
