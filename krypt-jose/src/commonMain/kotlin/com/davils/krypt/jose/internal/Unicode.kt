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

package com.davils.krypt.jose.internal

private const val NONCHARACTER_START: Int = 0xFDD0
private const val NONCHARACTER_END: Int = 0xFDEF
private const val PLANE_END_MASK: Int = 0xFFFE
private const val SUPPLEMENTARY_START: Int = 0x10000
private const val HIGH_SURROGATE_START: Int = 0xD800
private const val LOW_SURROGATE_START: Int = 0xDC00
private const val SURROGATE_BITS: Int = 10

internal object Unicode {
    fun isInterchangeable(text: CharSequence): Boolean {
        var index = 0
        var isValid = true
        while (index < text.length && isValid) {
            val char = text[index]
            val low = text.getOrNull(index + 1)
            val isPair = char.isHighSurrogate() && low != null && low.isLowSurrogate()
            val codePoint = when (isPair) {
                true -> pairOf(high = char.code, low = low.code)
                false -> char.code
            }
            isValid = !char.isSurrogate() || isPair
            isValid = isValid && isCharacter(codePoint)
            index += 1 + isPair.compareTo(false)
        }
        return isValid
    }

    fun isCharacter(codePoint: Int): Boolean {
        val isNoncharacter = codePoint in NONCHARACTER_START..NONCHARACTER_END ||
            codePoint and PLANE_END_MASK == PLANE_END_MASK
        return !isNoncharacter
    }

    fun pairOf(high: Int, low: Int): Int =
        (high - HIGH_SURROGATE_START shl SURROGATE_BITS) + (low - LOW_SURROGATE_START) + SUPPLEMENTARY_START
}
