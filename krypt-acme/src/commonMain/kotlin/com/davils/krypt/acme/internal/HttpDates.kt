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

package com.davils.krypt.acme.internal

import com.davils.krypt.acme.AcmeError
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private const val TEMPLATE: String = "___, __ ___ ____ __:__:__ GMT"
private const val FREE: Char = '_'
private const val MAXIMUM_DIGITS: Int = 10
private const val NAME_LENGTH: Int = 3
private const val DAY_START: Int = 5
private const val MONTH_START: Int = 8
private const val YEAR_START: Int = 12
private const val YEAR_LENGTH: Int = 4
private const val HOUR_START: Int = 17
private const val MINUTE_START: Int = 20
private const val SECOND_START: Int = 23
private const val LAST_HOUR: Int = 23
private const val LAST_MINUTE: Int = 59
private const val SECONDS_PER_MINUTE: Long = 60L
private const val SECONDS_PER_HOUR: Long = 3_600L
private const val SECONDS_PER_DAY: Long = 86_400L
private const val DAYS_PER_WEEK: Long = 7L
private const val EPOCH_WEEKDAY: Long = 4L
private const val DAYS_PER_ERA: Long = 146_097L
private const val EPOCH_SHIFT: Long = 719_468L
private const val YEARS_PER_ERA: Int = 400
private const val CENTURY: Int = 100
private const val LEAP_CYCLE: Int = 4
private const val DAYS_PER_YEAR: Int = 365
private const val MARCH: Int = 3
private const val MONTHS_PER_YEAR: Int = 12
private const val MONTH_FACTOR: Int = 153
private const val MONTH_OFFSET: Int = 2
private const val MONTH_DIVISOR: Int = 5
private const val FEBRUARY: Int = 2

internal object HttpDates {
    private val DAYS: List<String> = listOf("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
    private val MONTHS: List<String> =
        listOf("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    private val MONTH_DAYS: IntArray = intArrayOf(31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)

    fun retryAfter(value: String, now: Instant, maximum: Duration): Duration {
        val text = value.trim(' ', '\t')
        val isSeconds = text.isNotEmpty() && text.all { char -> char in '0'..'9' }
        val wait = when (isSeconds) {
            true -> secondsOf(text)
            false -> (parse(text) - now).coerceAtLeast(Duration.ZERO)
        }
        refuseUnless(condition = wait <= maximum, error = AcmeError.LimitExceeded)
        return wait
    }

    fun parse(text: String): Instant {
        val isShaped = text.length == TEMPLATE.length && TEMPLATE.indices.all { index -> fits(text, index) }
        refuseUnless(isShaped)
        val year = number(text = text, from = YEAR_START, length = YEAR_LENGTH)
        val monthName = text.substring(startIndex = MONTH_START, endIndex = MONTH_START + NAME_LENGTH)
        val month = MONTHS.indexOf(monthName) + 1
        val day = number(text = text, from = DAY_START, length = 2)
        val hour = number(text = text, from = HOUR_START, length = 2)
        val minute = number(text = text, from = MINUTE_START, length = 2)
        val second = number(text = text, from = SECOND_START, length = 2)
        val isTime = hour <= LAST_HOUR && minute <= LAST_MINUTE && second <= LAST_MINUTE
        refuseUnless(month > 0 && day in 1..daysIn(year = year, month = month) && isTime)
        val days = epochDays(year = year, month = month, day = day)
        val weekday = (days + EPOCH_WEEKDAY).mod(DAYS_PER_WEEK).toInt()
        refuseUnless(DAYS[weekday] == text.substring(startIndex = 0, endIndex = NAME_LENGTH))
        val seconds = days * SECONDS_PER_DAY + hour * SECONDS_PER_HOUR + minute * SECONDS_PER_MINUTE + second
        return Instant.fromEpochSeconds(seconds)
    }

    private fun fits(text: String, index: Int): Boolean {
        val expected = TEMPLATE[index]
        return expected == FREE || text[index] == expected
    }

    private fun secondsOf(text: String): Duration {
        refuseUnless(condition = text.length <= MAXIMUM_DIGITS, error = AcmeError.LimitExceeded)
        return text.toLong().seconds
    }

    private fun number(text: String, from: Int, length: Int): Int {
        val digits = text.substring(startIndex = from, endIndex = from + length)
        refuseUnless(digits.all { char -> char in '0'..'9' })
        return digits.toInt()
    }

    private fun daysIn(year: Int, month: Int): Int {
        val isLeap = year % LEAP_CYCLE == 0 && (year % CENTURY != 0 || year % YEARS_PER_ERA == 0)
        val extra = when (isLeap && month == FEBRUARY) {
            true -> 1
            false -> 0
        }
        return MONTH_DAYS[month - 1] + extra
    }

    private fun epochDays(year: Int, month: Int, day: Int): Long {
        val isEarly = month < MARCH
        val shiftedYear = when (isEarly) {
            true -> year - 1
            false -> year
        }
        val shiftedMonth = when (isEarly) {
            true -> month + MONTHS_PER_YEAR - MARCH
            false -> month - MARCH
        }
        val era = (shiftedYear + YEARS_PER_ERA) / YEARS_PER_ERA - 1
        val yearOfEra = shiftedYear - era * YEARS_PER_ERA
        val dayOfYear = (MONTH_FACTOR * shiftedMonth + MONTH_OFFSET) / MONTH_DIVISOR + day - 1
        val dayOfEra = yearOfEra * DAYS_PER_YEAR + yearOfEra / LEAP_CYCLE - yearOfEra / CENTURY + dayOfYear
        return era * DAYS_PER_ERA + dayOfEra - EPOCH_SHIFT
    }
}
