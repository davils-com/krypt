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

package com.davils.krypt.testing.acme

import com.davils.krypt.jose.JsonValue

internal fun json(vararg members: Pair<String, JsonValue?>): JsonValue.Object =
    JsonValue.Object(members.mapNotNull { (name, value) -> value?.let { found -> name to found } })

internal fun text(value: String?): JsonValue.Text? = value?.let { found -> JsonValue.Text(found) }

internal fun texts(values: List<String>): JsonValue.Array =
    JsonValue.Array(values.map { value -> JsonValue.Text(value) })

internal fun JsonValue.Object.textOf(name: String): String? = (this[name] as? JsonValue.Text)?.value

internal fun JsonValue.Object.objectOf(name: String): JsonValue.Object? = this[name] as? JsonValue.Object

internal fun JsonValue.Object.itemsOf(name: String): List<JsonValue> = (this[name] as? JsonValue.Array)?.items.orEmpty()

internal fun JsonValue.Object.longOf(name: String): Long? = (this[name] as? JsonValue.Integer)?.value

internal fun JsonValue.Object.isTrue(name: String): Boolean = this[name] == JsonValue.Bool(true)

internal fun JsonValue.textOrNull(): String? = (this as? JsonValue.Text)?.value
