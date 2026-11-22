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

import com.davils.krypt.cose.cbor.CborFloat
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import kotlin.math.floor
import kotlin.time.Instant

internal object NumericDates {
    private const val NANOS: Double = 1_000_000_000.0
    private const val LIMIT: Double = 1.0e15

    fun of(item: CborItem): Instant? {
        val seconds = item.longOrNull()?.let { value -> Instant.fromEpochSeconds(value) }
        val number = item.floatOrNull()
        return seconds ?: number?.let { found -> ofFloat(found.value) }
    }

    fun itemOf(instant: Instant): CborItem {
        val whole = CborInteger.of(instant.epochSeconds).takeIf { instant.nanosecondsOfSecond == 0 }
        return whole ?: CborFloat(instant.epochSeconds + instant.nanosecondsOfSecond / NANOS)
    }

    private fun ofFloat(value: Double): Instant? {
        val isRanged = value.isFinite() && value in -LIMIT..LIMIT
        val seconds = floor(value)
        val nanos = ((value - seconds) * NANOS).toInt()
        return Instant.fromEpochSeconds(seconds.toLong(), nanos).takeIf { isRanged }
    }
}
