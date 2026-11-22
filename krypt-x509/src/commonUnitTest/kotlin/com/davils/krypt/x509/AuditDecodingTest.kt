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
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.x509.extension.ExtensionIds
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.certificates
import com.davils.krypt.x509.fixture.crypto
import com.davils.krypt.x509.fixture.der
import com.davils.krypt.x509.name.distinguishedName
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Duration.Companion.days

private suspend fun signedWith(body: DerWriter.() -> Unit): ByteString {
    val pair = crypto.keys.generate(KeyType.P256)
    val signer = crypto.signatures.signer(pair.privateKey)
    val name = distinguishedName { commonName("audit") }
    val algorithm = AlgorithmIdentifiers.encode(signer.algorithm)
    val tbs = der {
        sequence {
            body()
            integer(1L)
            raw(algorithm)
            raw(name.encoded)
            sequence {
                time(NOW)
                time(NOW + 1.days)
            }
            raw(name.encoded)
            raw(pair.publicKey.encoded)
        }
    }
    val withExtensions = tbs
    val signature = signer.sign(withExtensions)
    return der {
        sequence {
            raw(withExtensions)
            raw(algorithm)
            bitString(BitString(signature))
        }
    }
}

private suspend fun signedTbs(tbs: ByteString): ByteString {
    val pair = crypto.keys.generate(KeyType.P256)
    val signer = crypto.signatures.signer(pair.privateKey)
    val signature = signer.sign(tbs)
    return der {
        sequence {
            raw(tbs)
            raw(AlgorithmIdentifiers.encode(signer.algorithm))
            bitString(BitString(signature))
        }
    }
}

class AuditDecodingTest : FunSpec({
    test("an explicitly encoded default version is refused") {
        val encoded = signedWith { explicit(0) { integer(0L) } }
        certificates.decode(encoded).getOrNull() shouldBe null
    }

    test("an explicitly encoded critical flag of false is refused") {
        val pair = crypto.keys.generate(KeyType.P256)
        val name = distinguishedName { commonName("audit") }
        val algorithm = AlgorithmIdentifiers.encode(crypto.signatures.signer(pair.privateKey).algorithm)
        val tbs = der {
            sequence {
                explicit(0) { integer(2L) }
                integer(1L)
                raw(algorithm)
                raw(name.encoded)
                sequence {
                    time(NOW)
                    time(NOW + 1.days)
                }
                raw(name.encoded)
                raw(pair.publicKey.encoded)
                explicit(3) {
                    sequence {
                        sequence {
                            objectIdentifier(ExtensionIds.SubjectKeyIdentifier)
                            boolean(false)
                            octetString(der { octetString(ByteString(1, 2, 3)) })
                        }
                    }
                }
            }
        }
        certificates.decode(signedTbs(tbs)).getOrNull() shouldBe null
    }
})
