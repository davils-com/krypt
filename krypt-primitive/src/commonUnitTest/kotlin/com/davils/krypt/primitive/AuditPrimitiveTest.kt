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
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.exchange.HpkeSuite
import com.davils.krypt.primitive.fixture.RfcKeys
import com.davils.krypt.primitive.fixture.crypto
import com.davils.krypt.primitive.fixture.fastCrypto
import com.davils.krypt.primitive.fixture.hex
import com.davils.krypt.primitive.password.PasswordVerification
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString

private const val ED25519_OID: String = "1.3.101.112"
private const val SALT: String = "000102030405060708090a0b0c0d0e0f"
private const val FAST_ITERATIONS: Int = 1_000
private const val DERIVED_BYTES: Int = 32
private const val X25519_ENC: Int = 32
private const val P256_FIELD: Int = 32

private suspend fun derived(text: String): SecretBytes = fastCrypto.derivations.pbkdf2(
    password = SecretText.of(text),
    salt = hex(SALT),
    iterations = FAST_ITERATIONS,
    length = DERIVED_BYTES,
)

class AuditPrimitiveTest : FunSpec({
    test("A-6: a PKCS #8 key whose embedded public key does not belong to it is refused") {
        val wrongPublic = ByteArray(X25519_ENC) { index -> index.toByte() }
        val pkcs8 = Der.encode {
            sequence {
                integer(1L)
                sequence { objectIdentifier(ObjectIdentifier.of(ED25519_OID)) }
                octetString(hex("0420" + RfcKeys.ED25519_SECRET))
                element(tag = Tag.context(number = 1, isConstructed = false), content = ByteString(byteArrayOf(0) + wrongPublic))
            }
        }
        val key = crypto.keys.decodePrivate(SecretBytes.copyOf(pkcs8)).getOrNull()
        val genuine = hex(RfcKeys.ED25519_SPKI_PREFIX + RfcKeys.ED25519_PUBLIC)
        (key == null || key.publicKey?.encoded == genuine) shouldBe true
    }

})
