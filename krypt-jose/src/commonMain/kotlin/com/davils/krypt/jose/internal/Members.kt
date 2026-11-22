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
import kotlinx.io.bytestring.ByteString

internal fun JsonValue.Object.textOf(name: String): String? = (this[name] as? JsonValue.Text)?.value

internal fun JsonValue.Object.stringsOf(name: String): List<String>? {
    val items = (this[name] as? JsonValue.Array)?.items ?: return null
    return items.mapNotNull { item -> (item as? JsonValue.Text)?.value }
}

internal fun JsonValue.Object.text(name: String): String? {
    val value = this[name] ?: return null
    require(value is JsonValue.Text)
    return value.value
}

internal fun JsonValue.Object.requiredText(name: String): String = requireNotNull(text(name))

internal fun JsonValue.Object.integer(name: String): Long? {
    val value = this[name] ?: return null
    require(value is JsonValue.Integer)
    return value.value
}

internal fun JsonValue.Object.bool(name: String): Boolean? {
    val value = this[name] ?: return null
    require(value is JsonValue.Bool)
    return value.isTrue
}

internal fun JsonValue.Object.member(name: String): JsonValue.Object? {
    val value = this[name] ?: return null
    require(value is JsonValue.Object)
    return value
}

internal fun JsonValue.Object.strings(name: String): List<String>? {
    val value = this[name] ?: return null
    require(value is JsonValue.Array)
    return value.items.map { item ->
        require(item is JsonValue.Text)
        item.value
    }
}

internal fun JsonValue.Object.bytes(name: String): ByteString? {
    val text = text(name) ?: return null
    return requireNotNull(Base64Url.decode(text))
}

internal fun JsonValue.Object.without(names: Set<String>): JsonValue.Object =
    JsonValue.Object(members.filterNot { member -> member.first in names })

internal fun text(value: String): JsonValue.Text = JsonValue.Text(value)

internal fun encoded(bytes: ByteString): JsonValue.Text = JsonValue.Text(Base64Url.encode(bytes))

internal fun merged(parts: List<JsonValue.Object>): JsonValue.Object =
    JsonValue.Object(parts.flatMap { part -> part.members })

internal fun requireDisjoint(parts: List<JsonValue.Object>) {
    merged(parts)
}
