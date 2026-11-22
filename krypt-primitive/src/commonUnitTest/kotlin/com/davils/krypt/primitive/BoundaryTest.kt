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

package com.davils.krypt.primitive

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.pem.Pem
import com.davils.krypt.asn1.pem.PemBlock
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.fixture.OpenSslKeys
import com.davils.krypt.primitive.fixture.RfcKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.fixture.utf8
import com.davils.krypt.primitive.key.KeyFailure
import com.davils.krypt.primitive.password.PasswordVerification
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val MESSAGE: String = "boundary"
private const val X25519_RAW: Int = 32
private const val UNUSED: Int = 1
private const val HUGE_SALT: Int = 2_048
private const val EC_OID: String = "1.2.840.10045.2.1"
private const val RSA_OID: String = "1.2.840.113549.1.1.1"

private fun DerWriter.algorithm(oid: String, parameters: DerWriter.() -> Unit = {}) {
    sequence {
        objectIdentifier(ObjectIdentifier.of(oid))
        parameters()
    }
}

private fun spki(oid: String, bits: BitString, parameters: DerWriter.() -> Unit = {}): ByteString = Der.encode {
    sequence {
        algorithm(oid, parameters)
        bitString(bits)
    }
}

class BoundaryTest : FunSpec({
    test("public keys with unused bits, missing curves or an empty modulus are refused") {
        val unused = spki("1.3.101.110", BitString(bytes = ByteString(ByteArray(X25519_RAW)), unusedBits = UNUSED))
        crypto.keys.decodePublic(unused).failureOrNull() shouldBe KeyFailure.Malformed
        crypto.keys.decodePublic(spki(EC_OID, BitString(ByteString(ByteArray(X25519_RAW))))).failureOrNull() shouldBe
            KeyFailure.UnsupportedAlgorithm
        val empty = Der.encode {
            sequence {
                integer(0L)
                integer(1L)
            }
        }
        val zeroModulus = spki(RSA_OID, BitString(empty)) { nullValue() }
        crypto.keys.decodePublic(zeroModulus).failureOrNull() shouldBe KeyFailure.Refused
    }

    test("an ECDSA signature with a negative s is invalid") {
        val pair = crypto.keys.generate(KeyType.P256)
        val negative = Der.encode {
            sequence {
                integer(1L)
                integer(-1L)
            }
        }
        crypto.signatures.verify(
            key = pair.publicKey,
            data = utf8(MESSAGE),
            signature = negative,
        ) shouldBe Verification.Invalid
    }

    test("HPKE refuses a recipient of another family and a sender without its public key") {
        val ed25519 = crypto.keys.generate(KeyType.Ed25519)
        shouldThrow<IllegalArgumentException> {
            crypto.hpke.sender(
                suite = HpkeSuite.P384Aes256Gcm,
                recipient = ed25519.publicKey,
            )
        }
        val recipient = crypto.keys.generate(KeyType.X25519)
        val encoding = SecretBytes.copyOf(hex(RfcKeys.X25519_PKCS8_PREFIX + RfcKeys.X25519_ALICE_SECRET))
        val anonymous = checkNotNull(crypto.keys.decodePrivate(encoding).getOrNull())
        shouldThrow<IllegalStateException> {
            crypto.hpke.sender(suite = HpkeSuite.X25519Aes256Gcm, recipient = recipient.publicKey, sender = anonymous)
        }
    }

    test("a hash that is too short for its length is malformed") {
        val hash = "\$pbkdf2-sha256\$i=1000,l=8\$AAAAAAAAAAAAAAAAAAAAAA\$AAAAAAAAAAA"
        fastCrypto.passwords.verify(SecretText.of(MESSAGE), hash) shouldBe PasswordVerification.Malformed
    }

    test("a PEM header that does not encrypt is read through") {
        val block = PemBlock(
            label = "RSA PRIVATE KEY",
            bytes = hex(OpenSslKeys.RSA_PKCS1),
            headers = listOf("Proc-Type" to "4,MIC-ONLY"),
        )
        val body = Pem.encode(listOf(block)).lines()
        val text = (listOf(body.first(), "Proc-Type: 4,MIC-ONLY", "") + body.drop(1)).joinToString("\n")
        crypto.keys.decodePrivatePem(text).isSuccess shouldBe true
    }

    test("an encrypted key with an oversized salt is refused") {
        val oversized = Der.encode {
            sequence {
                algorithm("1.2.840.113549.1.5.13") {
                    sequence {
                        algorithm("1.2.840.113549.1.5.12") {
                            sequence {
                                octetString(ByteString(ByteArray(HUGE_SALT)))
                                integer(1L)
                            }
                        }
                    }
                }
                octetString(ByteString())
            }
        }
        val refused = fastCrypto.keys.decrypt(oversized, SecretText.of(MESSAGE))
        refused.failureOrNull() shouldBe KeyFailure.UnsupportedEncryption
    }
})
