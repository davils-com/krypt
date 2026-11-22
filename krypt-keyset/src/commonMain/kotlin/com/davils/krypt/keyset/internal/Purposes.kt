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

package com.davils.krypt.keyset.internal

import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readText
import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.primitive.exchange.HpkeSuite

private const val AEAD: String = "aead"
private const val MAC: String = "mac"
private const val SIGNING: String = "signing"
private const val HYBRID: String = "hybrid"
private const val HYBRID_PARTS: Int = 3

internal object Purposes {
    fun DerWriter.writePurpose(purpose: KeyPurpose) {
        sequence {
            namesOf(purpose).forEach { name -> utf8String(name) }
        }
    }

    fun DerReader.readPurpose(): KeyPurpose? = readSequence {
        val kind = readText(Tag.Utf8String)
        val names = mutableListOf<String>()
        while (!isExhausted) names += readText(Tag.Utf8String)
        purposeOf(kind, names)
    }

    private fun namesOf(purpose: KeyPurpose): List<String> = when (purpose) {
        is KeyPurpose.Aead -> listOf(AEAD, purpose.algorithm.name)

        is KeyPurpose.Mac -> listOf(MAC, purpose.algorithm.name)

        is KeyPurpose.Signing -> listOf(SIGNING, purpose.type.name)

        is KeyPurpose.Hybrid -> listOf(
            HYBRID,
            purpose.suite.kem.name,
            purpose.suite.kdf.name,
            purpose.aead.name,
        )
    }

    private fun purposeOf(kind: String, names: List<String>): KeyPurpose? {
        val readers = mapOf<String, (List<String>) -> KeyPurpose?>(
            AEAD to { parts -> single(parts, AeadAlgorithm.entries)?.let { algorithm -> KeyPurpose.Aead(algorithm) } },
            MAC to { parts -> single(parts, MacAlgorithm.entries)?.let { algorithm -> KeyPurpose.Mac(algorithm) } },
            SIGNING to { parts -> signingOf(parts) },
            HYBRID to { parts -> hybridOf(parts) },
        )
        return readers[kind]?.invoke(names)
    }

    private fun signingOf(names: List<String>): KeyPurpose? {
        val type = single(names, KeyType.entries)
        return type?.takeIf { found -> found in KeyTypes.SIGNING }?.let { found -> KeyPurpose.Signing(found) }
    }

    private fun hybridOf(names: List<String>): KeyPurpose? {
        val parts = names.takeIf { found -> found.size == HYBRID_PARTS } ?: return null
        val kem = KemAlgorithm.entries.firstOrNull { entry -> entry.name == parts[0] }
        val kdf = KdfAlgorithm.entries.firstOrNull { entry -> entry.name == parts[1] }
        val aead = AeadAlgorithm.entries.firstOrNull { entry -> entry.name == parts[2] }
        return suiteOf(kem = kem, kdf = kdf, aead = aead)?.let { suite -> KeyPurpose.Hybrid(suite) }
    }

    private fun suiteOf(kem: KemAlgorithm?, kdf: KdfAlgorithm?, aead: AeadAlgorithm?): HpkeSuite? {
        val isComplete = kem != null && kdf != null && aead != null
        if (!isComplete || kdf.isPasswordBased || aead == AeadAlgorithm.Aes192Gcm) return null
        return HpkeSuite(kem = kem, kdf = kdf, aead = aead)
    }

    private fun <E : Enum<E>> single(names: List<String>, entries: List<E>): E? {
        val name = names.singleOrNull() ?: return null
        return entries.firstOrNull { entry -> entry.name == name }
    }
}
