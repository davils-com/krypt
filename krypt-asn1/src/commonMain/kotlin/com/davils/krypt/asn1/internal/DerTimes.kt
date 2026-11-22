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

package com.davils.krypt.asn1.internal

import kotlin.time.Instant

private const val UTC_LENGTH: Int = 13
private const val GENERALIZED_LENGTH: Int = 15
private const val UTC_PIVOT: Int = 50
private const val CENTURY_19: Int = 1_900
private const val CENTURY_20: Int = 2_000
private const val FIRST_UTC_YEAR: Int = 1_950
private const val LAST_UTC_YEAR: Int = 2_049
private const val MAXIMUM_FRACTION_DIGITS: Int = 9
private const val YEAR_DIGITS: Int = 4
private const val PAIR: Int = 2
private const val ZULU: Char = 'Z'
private const val FRACTION_MARK: Char = '.'
private const val FIELDS: Int = 5
private const val DAY: Int = 1
private const val MINUTE: Int = 3
private const val MONTH: Int = 0
private const val SECOND: Int = 4
private const val HOUR: Int = 2
private const val LAST_YEAR: Int = 9_999

internal object DerTimes {
    fun utcTimeOrNull(text: String): Instant? {
        val digits = text.takeIf { candidate -> candidate.length == UTC_LENGTH && candidate.last() == ZULU }
        val shortYear = digits?.let { value -> numberOrNull(text = value, from = 0, length = PAIR) } ?: return null
        val century = listOf(CENTURY_20, CENTURY_19)[(shortYear >= UTC_PIVOT).compareTo(false)]
        return civilOrNull(text = text, year = century + shortYear, from = PAIR, nanosecond = 0)?.toInstant()
    }

    fun generalizedTimeOrNull(text: String): Instant? {
        val isShaped = text.length >= GENERALIZED_LENGTH && text.last() == ZULU
        val year = text.takeIf { isShaped }?.let { value ->
            numberOrNull(
                text = value,
                from = 0,
                length = YEAR_DIGITS,
            )
        } ?: return null
        val fraction = text.substring(startIndex = GENERALIZED_LENGTH - 1, endIndex = text.length - 1)
        val nanosecond = fractionOrNull(fraction)
        val civil = nanosecond?.let { nanos ->
            civilOrNull(
                text = text,
                year = year,
                from = YEAR_DIGITS,
                nanosecond = nanos,
            )
        }
        return civil?.toInstant()
    }

    fun isUtcTimeYear(instant: Instant): Boolean = CivilTime.of(instant).year in FIRST_UTC_YEAR..LAST_UTC_YEAR

    fun utcTime(instant: Instant): String {
        val civil = CivilTime.of(instant)
        return pad(value = civil.year % (CENTURY_20 - CENTURY_19), length = PAIR) + clock(civil) + ZULU
    }

    fun generalizedTime(instant: Instant): String {
        val civil = CivilTime.of(instant)
        require(civil.year in 0..LAST_YEAR) { "A GeneralizedTime holds the years 0 to $LAST_YEAR, not ${civil.year}" }
        val fraction = fractionOf(civil.nanosecond)
        return pad(value = civil.year, length = YEAR_DIGITS) + clock(civil) + fraction + ZULU
    }

    private fun clock(civil: CivilTime): String = listOf(civil.month, civil.day, civil.hour, civil.minute, civil.second)
        .joinToString(separator = "") { value -> pad(value = value, length = PAIR) }

    private fun fractionOf(nanosecond: Int): String {
        val digits = pad(value = nanosecond, length = MAXIMUM_FRACTION_DIGITS).trimEnd('0')
        return listOf("", "$FRACTION_MARK$digits")[digits.isNotEmpty().compareTo(false)]
    }

    private fun civilOrNull(text: String, year: Int, from: Int, nanosecond: Int): CivilTime? {
        val fields = (0 until FIELDS).map { index ->
            numberOrNull(
                text = text,
                from = from + index * PAIR,
                length = PAIR,
            )
        }
        val values = fields.filterNotNull().takeIf { found -> found.size == FIELDS } ?: return null
        val civil = CivilTime(
            year = year,
            month = values[MONTH],
            day = values[DAY],
            hour = values[HOUR],
            minute = values[MINUTE],
            second = values[SECOND],
            nanosecond = nanosecond,
        )
        return civil.takeIf { candidate -> candidate.isValid }
    }

    private fun fractionOrNull(fraction: String): Int? {
        val isEmpty = fraction.isEmpty()
        val digits = fraction.removePrefix(FRACTION_MARK.toString())
        val isCanonical = fraction.startsWith(FRACTION_MARK) &&
            digits.length in 1..MAXIMUM_FRACTION_DIGITS &&
            digits.all { char -> char in '0'..'9' } &&
            !digits.endsWith('0')
        val padded = digits.padEnd(MAXIMUM_FRACTION_DIGITS, '0')
        val nanos = padded.toIntOrNull()?.takeIf { isCanonical }
        return listOf(nanos, 0)[isEmpty.compareTo(false)]
    }

    private fun numberOrNull(text: String, from: Int, length: Int): Int? {
        val part = text.substring(startIndex = from, endIndex = from + length)
        val isDigits = part.all { char -> char in '0'..'9' }
        return part.takeIf { isDigits }?.toInt()
    }

    private fun pad(value: Int, length: Int): String = value.toString().padStart(length, '0')
}
