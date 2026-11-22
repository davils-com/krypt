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

package com.davils.krypt.keyset

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.Der
import com.davils.krypt.keyset.fixture.keysets
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val SAFE_KDF: String = "HkdfSha256"
private const val SAFE_AEAD: String = "Aes256Gcm"
private const val UNKNOWN: String = "Unknown"

private fun hybridPublicKeyset(kem: String = "DhkemX25519", kdf: String, aead: String): ByteString = Der.encode {
    sequence {
        integer(1L)
        sequence {
            utf8String("hybrid")
            utf8String(kem)
            utf8String(kdf)
            utf8String(aead)
        }
        octetString(ByteString(ByteArray(KeyId.SIZE)))
        sequence { }
    }
}

class HybridSuiteDecodingTest : FunSpec({
    test("a public key set whose HPKE suite derives with a password KDF is unsupported") {
        val encoded = hybridPublicKeyset(kdf = "Pbkdf2Sha256", aead = SAFE_AEAD)
        keysets.decodePublic(encoded) shouldBe Outcome.Failure(KeysetFailure.Unsupported)
    }

    test("a public key set whose HPKE suite seals with AES-192-GCM is unsupported") {
        val encoded = hybridPublicKeyset(kdf = SAFE_KDF, aead = "Aes192Gcm")
        keysets.decodePublic(encoded) shouldBe Outcome.Failure(KeysetFailure.Unsupported)
    }

    test("a public key set whose HPKE suite names an unknown algorithm is unsupported") {
        val cases = listOf(
            hybridPublicKeyset(kem = UNKNOWN, kdf = SAFE_KDF, aead = SAFE_AEAD),
            hybridPublicKeyset(kdf = UNKNOWN, aead = SAFE_AEAD),
            hybridPublicKeyset(kdf = SAFE_KDF, aead = UNKNOWN),
        )
        cases.forEach { encoded ->
            keysets.decodePublic(encoded) shouldBe Outcome.Failure(KeysetFailure.Unsupported)
        }
    }
})
