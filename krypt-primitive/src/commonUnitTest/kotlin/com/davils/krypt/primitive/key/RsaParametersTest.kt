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

package com.davils.krypt.primitive.key

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.primitive.fixture.crypto
import io.kotest.core.spec.style.FunSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val RSA_OID: String = "1.2.840.113549.1.1.1"
private const val MODULUS_BYTES: Int = 384
private const val FERMAT_EXPONENT: Long = 65_537
private const val PRIVATE_FIELDS: Int = 6
private const val HUGE_EXPONENT_BYTES: Int = 33

private enum class Parameters { Null, Absent, Integer }

private fun magnitude(size: Int, last: Int): DerInteger {
    val bytes = ByteArray(size) { 0x5A }.also { array ->
        array[0] = 0xC0.toByte()
        array[size - 1] = last.toByte()
    }
    return DerInteger.ofMagnitude(ByteString(bytes))
}

private val strongModulus: DerInteger = magnitude(size = MODULUS_BYTES, last = 0x01)

private val fermat: DerInteger = DerInteger.of(FERMAT_EXPONENT)

private fun DerWriter.rsaAlgorithm(parameters: Parameters) {
    sequence {
        objectIdentifier(ObjectIdentifier.of(RSA_OID))
        when (parameters) {
            Parameters.Null -> nullValue()
            Parameters.Absent -> Unit
            Parameters.Integer -> integer(0L)
        }
    }
}

private fun spki(modulus: DerInteger, exponent: DerInteger, parameters: Parameters = Parameters.Null): ByteString {
    val publicKey = Der.encode {
        sequence {
            integer(modulus)
            integer(exponent)
        }
    }
    return Der.encode {
        sequence {
            rsaAlgorithm(parameters)
            bitString(BitString(publicKey))
        }
    }
}

private fun pkcs8(modulus: DerInteger, exponent: DerInteger, parameters: Parameters = Parameters.Null): SecretBytes {
    val encoded = Der.encode {
        sequence {
            integer(0L)
            rsaAlgorithm(parameters)
            octetStringOf {
                sequence {
                    integer(0L)
                    integer(modulus)
                    integer(exponent)
                    repeat(PRIVATE_FIELDS) { integer(DerInteger.of(1L)) }
                }
            }
        }
    }
    return SecretBytes.copyOf(encoded)
}

class RsaParametersTest : FunSpec({
    context("RSA keys with a modulus or an exponent RSA does not allow are malformed, never an exception") {
        withData(
            nameFn = { (name, _) -> name },
            listOf(
                "a negative modulus" to (DerInteger.of(-1L) to fermat),
                "an even modulus" to (magnitude(size = MODULUS_BYTES, last = 0x02) to fermat),
                "a zero modulus" to (DerInteger.Zero to fermat),
                "an exponent of one" to (strongModulus to DerInteger.of(1L)),
                "an even exponent" to (strongModulus to DerInteger.of(FERMAT_EXPONENT + 1)),
                "a negative exponent" to (strongModulus to DerInteger.of(-FERMAT_EXPONENT)),
                "an exponent of 2^256 and more" to (strongModulus to magnitude(size = HUGE_EXPONENT_BYTES, last = 1)),
            ),
        ) { (_, values) ->
            val (modulus, exponent) = values
            crypto.keys.decodePublic(spki(modulus = modulus, exponent = exponent)) shouldBe
                Outcome.Failure(KeyFailure.Malformed)
            crypto.keys.decodePrivate(pkcs8(modulus = modulus, exponent = exponent)) shouldBe
                Outcome.Failure(KeyFailure.Malformed)
        }
    }

    test("the AlgorithmIdentifier of rsaEncryption must carry NULL parameters") {
        val absent = spki(modulus = strongModulus, exponent = fermat, parameters = Parameters.Absent)
        crypto.keys.decodePublic(absent) shouldBe Outcome.Failure(KeyFailure.Malformed)
        val integer = spki(modulus = strongModulus, exponent = fermat, parameters = Parameters.Integer)
        crypto.keys.decodePublic(integer) shouldBe Outcome.Failure(KeyFailure.Malformed)
        val privateAbsent = pkcs8(modulus = strongModulus, exponent = fermat, parameters = Parameters.Absent)
        crypto.keys.decodePrivate(privateAbsent) shouldBe Outcome.Failure(KeyFailure.Malformed)
    }

    test("an RSA key with an odd modulus and a sane exponent is read") {
        val largest = magnitude(size = HUGE_EXPONENT_BYTES - 1, last = 1)
        crypto.keys.decodePublic(spki(modulus = strongModulus, exponent = largest)).isSuccess shouldBe true
        crypto.keys.decodePublic(spki(modulus = strongModulus, exponent = DerInteger.of(3L))).isSuccess shouldBe true
    }
})
