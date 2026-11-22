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

internal object Utf8 {
    private const val UNSIGNED: Int = 0xff
    private val CONTINUATION: IntRange = 0x80..0xbf
    private val RULES: List<Utf8Rule> = listOf(
        Utf8Rule(leads = 0x00..0x7f, count = 1, second = CONTINUATION),
        Utf8Rule(leads = 0xc2..0xdf, count = 2, second = CONTINUATION),
        Utf8Rule(leads = 0xe0..0xe0, count = 3, second = 0xa0..0xbf),
        Utf8Rule(leads = 0xe1..0xec, count = 3, second = CONTINUATION),
        Utf8Rule(leads = 0xed..0xed, count = 3, second = 0x80..0x9f),
        Utf8Rule(leads = 0xee..0xef, count = 3, second = CONTINUATION),
        Utf8Rule(leads = 0xf0..0xf0, count = 4, second = 0x90..0xbf),
        Utf8Rule(leads = 0xf1..0xf3, count = 4, second = CONTINUATION),
        Utf8Rule(leads = 0xf4..0xf4, count = 4, second = 0x80..0x8f),
    )

    fun isValid(bytes: ByteArray): Boolean {
        var index = 0
        while (index < bytes.size) {
            val length = sequenceLength(bytes, index)
            if (length == 0) return false
            index += length
        }
        return true
    }

    fun isWellFormed(text: String): Boolean {
        var index = 0
        var isValid = true
        while (isValid && index < text.length) {
            val char = text[index]
            val isHigh = char.isHighSurrogate()
            val isPaired = isHigh && index + 1 < text.length && text[index + 1].isLowSurrogate()
            isValid = !char.isLowSurrogate() && isHigh == isPaired
            index += 1 + isPaired.compareTo(false)
        }
        return isValid
    }

    private fun isContinued(bytes: ByteArray, index: Int, rule: Utf8Rule, offsets: IntRange): Boolean =
        offsets.all { offset -> isContinuation(bytes = bytes, position = index + offset, rule = rule, offset = offset) }

    private fun isContinuation(bytes: ByteArray, position: Int, rule: Utf8Rule, offset: Int): Boolean {
        val byte = bytes[position].toInt() and UNSIGNED
        val range = rule.second.takeIf { offset == 1 } ?: CONTINUATION
        return byte in range
    }

    private fun sequenceLength(bytes: ByteArray, index: Int): Int {
        val lead = bytes[index].toInt() and UNSIGNED
        val rule = RULES.firstOrNull { candidate -> lead in candidate.leads } ?: return 0
        val isComplete = index + rule.count <= bytes.size
        val offsets = 1 until rule.count
        val isValid = isComplete && isContinued(bytes = bytes, index = index, rule = rule, offsets = offsets)
        return rule.count.takeIf { isValid } ?: 0
    }
}
