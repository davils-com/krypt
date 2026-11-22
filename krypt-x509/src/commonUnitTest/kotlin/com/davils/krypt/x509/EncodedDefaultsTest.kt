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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.x509

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.certificates
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.fixture.utf8
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days

private const val V1: Long = 0L
private const val V2: Long = 1L
private const val V3: Long = 2L
private const val EXTENSIONS: Int = 3
private const val KEY_ID: String = "key"

private val NAME: DistinguishedName = distinguishedName { commonName("defaults") }

private suspend fun signed(version: (DerWriter.() -> Unit)?, trailer: DerWriter.() -> Unit = {}): ByteString {
    val pair = crypto.keys.generate(KeyType.P256)
    val signer = crypto.signatures.signer(pair.privateKey)
    val algorithm = AlgorithmIdentifiers.encode(signer.algorithm)
    val key = pair.publicKey.encoded
    val tbs = der {
        sequence {
            version?.let { write -> explicit(0) { write() } }
            integer(1L)
            raw(algorithm)
            raw(NAME.encoded)
            sequence {
                time(NOW)
                time(NOW + 1.days)
            }
            raw(NAME.encoded)
            raw(key)
            trailer()
        }
    }
    val signature = signer.sign(tbs)
    return der {
        sequence {
            raw(tbs)
            raw(algorithm)
            bitString(BitString(signature))
        }
    }
}

private fun DerWriter.extensionList(isCritical: Boolean) {
    explicit(EXTENSIONS) {
        sequence {
            sequence {
                objectIdentifier(ExtensionIds.SubjectKeyIdentifier)
                boolean(isCritical)
                octetString(der { octetString(utf8(KEY_ID)) })
            }
        }
    }
}

private fun DerWriter.uniqueIdentifier() {
    bitString(BitString(ByteString(1)), Tag.context(number = 1, isConstructed = false))
}

class EncodedDefaultsTest : FunSpec({
    test("an explicitly encoded default version is refused") {
        certificates.decode(signed(version = { integer(V1) })).getOrNull() shouldBe null
        certificates.decode(signed(version = null)).getOrNull()?.version shouldBe 1
    }

    test("an explicitly encoded critical flag of false is refused") {
        val v3: DerWriter.() -> Unit = { integer(V3) }
        certificates.decode(signed(v3) { extensionList(isCritical = false) }).getOrNull() shouldBe null
        val critical = certificates.decode(signed(v3) { extensionList(isCritical = true) }).getOrNull()
        val all = checkNotNull(critical).extensions.all
        all.single().isCritical shouldBe true
    }

    test("unique identifiers are refused in version 1 and read in version 2") {
        certificates.decode(signed(version = null) { uniqueIdentifier() }).getOrNull() shouldBe null
        val v2 = certificates.decode(signed(version = { integer(V2) }) { uniqueIdentifier() }).getOrNull()
        v2?.version shouldBe 2
    }
})
