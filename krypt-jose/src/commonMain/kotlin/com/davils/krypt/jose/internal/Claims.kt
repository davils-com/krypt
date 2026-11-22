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

import com.davils.krypt.jose.JsonValue
import kotlin.time.Instant

internal fun JsonValue.Object.audienceOf(): List<String> {
    val single = textOf(ClaimNames.AUDIENCE)?.let { audience -> listOf(audience) }
    return single ?: stringsOf(ClaimNames.AUDIENCE).orEmpty()
}

internal fun JsonValue.Object.instantOf(name: String): Instant? =
    (this[name] as? JsonValue.Integer)?.let { date -> Instant.fromEpochSeconds(date.value) }

internal fun checkClaims(claims: JsonValue.Object) {
    ClaimNames.TEXTS.forEach { name -> claims.text(name) }
    ClaimNames.DATES.forEach { name -> claims.integer(name) }
    val audience = claims[ClaimNames.AUDIENCE]
    val isText = audience == null || audience is JsonValue.Text
    val isList = audience is JsonValue.Array &&
        audience.items.isNotEmpty() &&
        audience.items.all { item -> item is JsonValue.Text }
    require(isText || isList)
}
