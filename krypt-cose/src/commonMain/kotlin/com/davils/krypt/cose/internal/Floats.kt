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

package com.davils.krypt.cose.internal

import kotlin.math.abs
import kotlin.math.withSign

internal object Floats {
    private const val HALF_HEAD: Int = 0xf9
    private const val SINGLE_HEAD: Int = 0xfa
    private const val DOUBLE_HEAD: Int = 0xfb
    private const val HALF_BYTES: Int = 2
    private const val SINGLE_BYTES: Int = 4
    private const val DOUBLE_BYTES: Int = 8
    private const val CANONICAL_NAN: Int = 0x7e00
    private const val HALF_INFINITY: Int = 0x7c00
    private const val HALF_SIGN: Int = 0x8000
    private const val HALF_EXPONENT_MASK: Int = 0x1f
    private const val HALF_MANTISSA_MASK: Int = 0x3ff
    private const val HALF_MANTISSA_BITS: Int = 10
    private const val HALF_BIAS: Int = 15
    private const val HALF_MAXIMUM_EXPONENT: Int = 30
    private const val HALF_SIGN_SHIFT: Int = 15
    private const val FLOAT_EXPONENT_SHIFT: Int = 23
    private const val FLOAT_EXPONENT_MASK: Int = 0xff
    private const val FLOAT_MANTISSA_MASK: Int = 0x7fffff
    private const val FLOAT_BIAS: Int = 127
    private const val MANTISSA_DROP: Int = 13
    private const val DOUBLE_BIAS: Int = 1023
    private const val DOUBLE_SPECIAL: Long = 0x7ff
    private const val DOUBLE_EXPONENT_SHIFT: Int = 52
    private const val DOUBLE_MANTISSA_SHIFT: Int = 42
    private const val DOUBLE_SIGN_SHIFT: Int = 63
    private const val SUBNORMAL_SCALE: Double = 16_777_216.0
    private const val SINGLE_MASK: Long = 0xffff_ffffL

    fun encode(value: Double): ByteArray {
        val half = halfOf(value)
        val single = value.toFloat().takeIf { candidate -> candidate.toDouble() == value }
        val halfBytes = half?.let { bits -> withHead(HALF_HEAD, bits.toLong(), HALF_BYTES) }
        val singleBytes = single?.let { found ->
            withHead(SINGLE_HEAD, found.toRawBits().toLong() and SINGLE_MASK, SINGLE_BYTES)
        }
        return halfBytes ?: singleBytes ?: withHead(DOUBLE_HEAD, value.toRawBits(), DOUBLE_BYTES)
    }

    fun ofHalf(bits: Int): Double {
        val isNegative = bits ushr HALF_SIGN_SHIFT == 1
        val exponent = (bits ushr HALF_MANTISSA_BITS) and HALF_EXPONENT_MASK
        val mantissa = (bits and HALF_MANTISSA_MASK).toLong()
        val isSpecial = exponent == HALF_EXPONENT_MASK
        val biased = listOf(exponent.toLong() - HALF_BIAS + DOUBLE_BIAS, DOUBLE_SPECIAL)[isSpecial.compareTo(false)]
        val sign = isNegative.compareTo(false).toLong() shl DOUBLE_SIGN_SHIFT
        val normal = Double.fromBits(
            sign or (biased shl DOUBLE_EXPONENT_SHIFT) or (mantissa shl DOUBLE_MANTISSA_SHIFT),
        )
        val subnormal = (mantissa / SUBNORMAL_SCALE).withSign(listOf(1, -1)[isNegative.compareTo(false)])
        return subnormal.takeIf { exponent == 0 } ?: normal
    }

    fun ofSingle(bits: Int): Double = Float.fromBits(bits).toDouble()

    private fun halfOf(value: Double): Int? {
        if (value.isNaN()) return CANONICAL_NAN
        val sign = (value.toRawBits() ushr DOUBLE_SIGN_SHIFT).toInt() * HALF_SIGN
        val magnitude = abs(value)
        val bits = magnitude.toFloat().toRawBits()
        val exponent = ((bits ushr FLOAT_EXPONENT_SHIFT) and FLOAT_EXPONENT_MASK) - FLOAT_BIAS + HALF_BIAS
        val mantissa = bits and FLOAT_MANTISSA_MASK
        val normal = ((exponent shl HALF_MANTISSA_BITS) or (mantissa ushr MANTISSA_DROP)).takeIf {
            exponent in 1..HALF_MAXIMUM_EXPONENT
        }
        val subnormal = (magnitude * SUBNORMAL_SCALE).toInt().takeIf { exponent <= 0 }
        val candidate = sign or (normal ?: subnormal ?: HALF_INFINITY)
        return candidate.takeIf { ofHalf(candidate).toRawBits() == value.toRawBits() }
    }

    private fun withHead(head: Int, bits: Long, size: Int): ByteArray {
        val bytes = ByteArray(size + 1)
        bytes[0] = head.toByte()
        for (index in 0 until size) {
            bytes[index + 1] = (bits shr (size - 1 - index) * Byte.SIZE_BITS).toByte()
        }
        return bytes
    }
}
