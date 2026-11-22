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

private const val SECONDS_PER_DAY: Long = 86_400
private const val SECONDS_PER_HOUR: Long = 3_600
private const val SECONDS_PER_MINUTE: Long = 60
private const val DAYS_PER_ERA: Long = 146_097
private const val YEARS_PER_ERA: Long = 400
private const val EPOCH_SHIFT: Long = 719_468
private const val MONTHS_FROM_MARCH: Long = 153
private const val MARCH_OFFSET: Long = 3
private const val DAYS_IN_YEAR: Long = 365
private const val LEAP_EVERY: Long = 4
private const val CENTURY: Long = 100
private const val DECEMBER: Int = 12
private const val FEBRUARY: Int = 2
private const val SHORT_MONTH_DAYS: Int = 30
private const val LONG_MONTH_DAYS: Int = 31
private const val LEAP_FEBRUARY_DAYS: Int = 29
private const val FEBRUARY_DAYS: Int = 28
private const val DAY_CYCLE_SHIFT: Long = 2
private const val MONTH_CYCLE: Long = 5
private const val ERA_LAST_YEAR_DAYS: Long = 146_096
private const val CYCLE_DAYS: Long = 1_460
private const val CENTURY_DAYS: Long = 36_524
private const val MONTHS: Long = 12
private const val LAST_HOUR: Int = 23
private const val LAST_MINUTE: Int = 59
private val THIRTY_DAY_MONTHS: Set<Int> = setOf(4, 6, 9, 11)

internal class CivilTime(
    val year: Int,
    val month: Int,
    val day: Int,
    val hour: Int,
    val minute: Int,
    val second: Int,
    val nanosecond: Int,
) {
    val isValid: Boolean
        get() = month in 1..DECEMBER &&
            day in 1..daysIn(
                year,
                month,
            ) &&
            hour <= LAST_HOUR &&
            minute <= LAST_MINUTE &&
            second <= LAST_MINUTE

    fun toInstant(): Instant {
        val days = daysFromCivil(year = year.toLong(), month = month.toLong(), day = day.toLong())
        val seconds = days * SECONDS_PER_DAY + hour * SECONDS_PER_HOUR + minute * SECONDS_PER_MINUTE + second
        return Instant.fromEpochSeconds(epochSeconds = seconds, nanosecondAdjustment = nanosecond)
    }

    companion object {
        fun of(instant: Instant): CivilTime {
            val days = instant.epochSeconds.floorDiv(SECONDS_PER_DAY)
            val secondOfDay = instant.epochSeconds.mod(SECONDS_PER_DAY)
            val shifted = days + EPOCH_SHIFT
            val era = shifted.floorDiv(DAYS_PER_ERA)
            val dayOfEra = shifted - era * DAYS_PER_ERA
            val yearOfEra =
                (dayOfEra - dayOfEra / CYCLE_DAYS + dayOfEra / CENTURY_DAYS - dayOfEra / ERA_LAST_YEAR_DAYS) /
                    DAYS_IN_YEAR
            val dayOfYear = dayOfEra - (DAYS_IN_YEAR * yearOfEra + yearOfEra / LEAP_EVERY - yearOfEra / CENTURY)
            val monthIndex = (MONTH_CYCLE * dayOfYear + DAY_CYCLE_SHIFT) / MONTHS_FROM_MARCH
            val day = dayOfYear - (MONTHS_FROM_MARCH * monthIndex + DAY_CYCLE_SHIFT) / MONTH_CYCLE + 1
            val month = monthIndex + MARCH_OFFSET - MONTHS * (monthIndex >= MONTHS - MARCH_OFFSET + 1).compareTo(false)
            val year = yearOfEra + era * YEARS_PER_ERA + (month <= 2).compareTo(false)
            return CivilTime(
                year = year.toInt(),
                month = month.toInt(),
                day = day.toInt(),
                hour = (secondOfDay / SECONDS_PER_HOUR).toInt(),
                minute = (secondOfDay % SECONDS_PER_HOUR / SECONDS_PER_MINUTE).toInt(),
                second = (secondOfDay % SECONDS_PER_MINUTE).toInt(),
                nanosecond = instant.nanosecondsOfSecond,
            )
        }

        private fun daysFromCivil(year: Long, month: Long, day: Long): Long {
            val shiftedYear = year - (month <= 2).compareTo(false)
            val era = shiftedYear.floorDiv(YEARS_PER_ERA)
            val yearOfEra = shiftedYear - era * YEARS_PER_ERA
            val monthIndex = (month + MONTHS - MARCH_OFFSET) % MONTHS
            val dayOfYear = (MONTHS_FROM_MARCH * monthIndex + DAY_CYCLE_SHIFT) / MONTH_CYCLE + day - 1
            val dayOfEra = yearOfEra * DAYS_IN_YEAR + yearOfEra / LEAP_EVERY - yearOfEra / CENTURY + dayOfYear
            return era * DAYS_PER_ERA + dayOfEra - EPOCH_SHIFT
        }

        private fun daysIn(year: Int, month: Int): Int {
            val isLeap =
                year % LEAP_EVERY.toInt() == 0 && (year % CENTURY.toInt() != 0 || year % YEARS_PER_ERA.toInt() == 0)
            val february = FEBRUARY_DAYS + isLeap.compareTo(false) * (LEAP_FEBRUARY_DAYS - FEBRUARY_DAYS)
            val other = LONG_MONTH_DAYS -
                (month in THIRTY_DAY_MONTHS).compareTo(
                    false,
                ) *
                (LONG_MONTH_DAYS - SHORT_MONTH_DAYS)
            return listOf(other, february)[(month == FEBRUARY).compareTo(false)]
        }
    }
}
