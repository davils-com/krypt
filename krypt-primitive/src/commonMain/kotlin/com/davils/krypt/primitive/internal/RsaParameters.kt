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

package com.davils.krypt.primitive.internal

import com.davils.krypt.asn1.BitString
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.readInt
import com.davils.krypt.asn1.readRemaining
import kotlinx.io.bytestring.ByteString

private const val BYTE_BITS: Int = 8
private const val BYTE_MASK: Int = 0xFF
private const val MAXIMUM_VERSION: Int = 1
private const val SMALLEST_EXPONENT_VALUE: Long = 3
private const val MAXIMUM_EXPONENT_BYTES: Int = 32

internal object RsaParameters {
    private val SMALLEST_EXPONENT: DerInteger = DerInteger.of(SMALLEST_EXPONENT_VALUE)

    fun modulusOf(publicKey: ByteString): DerInteger? = Der.decodeOrNull(publicKey) {
        readSequence {
            val modulus = readInteger()
            modulus.takeIf { isValidRsa(modulus = modulus, exponent = readInteger()) }
        }
    }

    fun privateOf(privateKey: ByteString): Pair<DerInteger, BitString>? = Der.decodeOrNull(privateKey) {
        readSequence {
            readInt(0..MAXIMUM_VERSION)
            val modulus = readInteger()
            val exponent = readInteger()
            readRemaining()
            val public = modulus to publicBits(modulus = modulus, exponent = exponent)
            public.takeIf { isValidRsa(modulus = modulus, exponent = exponent) }
        }
    }

    fun publicBits(modulus: DerInteger, exponent: DerInteger): BitString {
        val encoded = Der.encode {
            sequence {
                integer(modulus)
                integer(exponent)
            }
        }
        return BitString(encoded)
    }

    fun bitLength(modulus: DerInteger): Int {
        val magnitude = modulus.magnitude().toByteArray()
        val lead = magnitude.firstOrNull()?.toInt() ?: 0
        val leadBits = Int.SIZE_BITS - (lead and BYTE_MASK).countLeadingZeroBits()
        return (magnitude.size - 1).coerceAtLeast(0) * BYTE_BITS + leadBits
    }

    private fun isValidRsa(modulus: DerInteger, exponent: DerInteger): Boolean {
        val isPositive = !modulus.isNegative && !exponent.isNegative
        return isPositive && isOdd(modulus) && isOdd(exponent) && isExponentInRange(exponent)
    }

    private fun isOdd(value: DerInteger): Boolean {
        val bytes = value.bytes
        return bytes[bytes.size - 1].toInt() and 1 == 1
    }

    private fun isExponentInRange(exponent: DerInteger): Boolean =
        exponent >= SMALLEST_EXPONENT && exponent.magnitude().size <= MAXIMUM_EXPONENT_BYTES
}
