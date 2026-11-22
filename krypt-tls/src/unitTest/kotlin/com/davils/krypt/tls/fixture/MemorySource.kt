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

package com.davils.krypt.tls.fixture

import com.davils.krypt.keystore.Identity
import com.davils.krypt.keystore.material.MaterialRead
import com.davils.krypt.keystore.material.MaterialRef
import com.davils.krypt.keystore.material.MaterialSource
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

internal class MemorySource : MaterialSource {
    private val files: MutableMap<String, ByteString> = mutableMapOf()

    var isBroken: Boolean = false

    override suspend fun read(ref: MaterialRef, maximumBytes: Int): MaterialRead {
        check(!isBroken) { "The disk is gone" }
        val bytes = files[ref.name] ?: return MaterialRead.Missing
        return MaterialRead.Found(bytes)
    }

    fun put(identity: Identity) {
        val certificate = Certificates(crypto).encodePem(identity.certificate)
        files[CERTIFICATE] = certificate.encodeToByteString()
        val key = crypto.keys.encodePem(identity.privateKey)
        files[KEY] = key.encodeToByteString()
    }

    fun put(vararg anchors: Certificate) {
        val codec = Certificates(crypto)
        val text = anchors.joinToString(separator = "") { anchor -> codec.encodePem(anchor) }
        files[ANCHORS] = text.encodeToByteString()
    }

    fun remove(name: String) {
        files.remove(name)
    }

    companion object {
        const val CERTIFICATE: String = "tls.crt"
        const val KEY: String = "tls.key"
        const val ANCHORS: String = "ca.crt"
    }
}
