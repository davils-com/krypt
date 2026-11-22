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

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.acme.AcmeError
import com.davils.krypt.acme.AcmeFailure
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.core.encoding.Base64Alphabet
import com.davils.krypt.jose.JsonValue
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString

internal fun refuse(error: AcmeError): Nothing = throw WireRefusal(error)

internal fun refuseUnless(condition: Boolean, error: AcmeError = AcmeError.Malformed) {
    if (!condition) refuse(error)
}

internal inline fun <T> reading(block: () -> T): Outcome<T, AcmeFailure> = try {
    Outcome.Success(block())
} catch (refusal: WireRefusal) {
    Outcome.Failure(refusal.error)
} catch (ignored: IllegalArgumentException) {
    Outcome.Failure(AcmeError.Malformed)
}

internal fun base64Url(bytes: ByteString): String =
    Base64.encode(bytes = bytes, alphabet = Base64Alphabet.Url, padding = false)

internal fun JsonValue.asText(): String = when (this) {
    is JsonValue.Text -> value
    is JsonValue.Integer, is JsonValue.Bool, JsonValue.Null, is JsonValue.Array, is JsonValue.Object -> mistyped()
}

internal fun JsonValue.asObject(): JsonValue.Object = when (this) {
    is JsonValue.Object -> this
    is JsonValue.Integer, is JsonValue.Bool, JsonValue.Null, is JsonValue.Array, is JsonValue.Text -> mistyped()
}

internal fun JsonValue.asItems(): List<JsonValue> = when (this) {
    is JsonValue.Array -> items
    is JsonValue.Integer, is JsonValue.Bool, JsonValue.Null, is JsonValue.Object, is JsonValue.Text -> mistyped()
}

internal fun JsonValue.asBoolean(): Boolean = when (this) {
    is JsonValue.Bool -> isTrue
    is JsonValue.Integer, is JsonValue.Array, JsonValue.Null, is JsonValue.Object, is JsonValue.Text -> mistyped()
}

internal fun JsonValue.asInteger(): Long = when (this) {
    is JsonValue.Integer -> value
    is JsonValue.Bool, is JsonValue.Array, JsonValue.Null, is JsonValue.Object, is JsonValue.Text -> mistyped()
}

internal fun JsonValue.Object.text(name: String): String? = this[name]?.asText()

internal fun JsonValue.Object.requiredText(name: String): String = text(name) ?: refuse(AcmeError.Malformed)

internal fun JsonValue.Object.member(name: String): JsonValue.Object? = this[name]?.asObject()

internal fun JsonValue.Object.bool(name: String): Boolean? = this[name]?.asBoolean()

internal fun JsonValue.Object.integer(name: String): Long? = this[name]?.asInteger()

internal fun JsonValue.Object.items(name: String, maximum: Int): List<JsonValue>? {
    val items = this[name]?.asItems()
    refuseUnless(condition = (items?.size ?: 0) <= maximum, error = AcmeError.LimitExceeded)
    return items
}

internal fun JsonValue.Object.texts(name: String, maximum: Int): List<String>? =
    items(name = name, maximum = maximum)?.map { item -> item.asText() }

internal fun text(value: String): JsonValue.Text = JsonValue.Text(value)

internal fun bytesOf(json: JsonValue.Object): ByteString = json.encode().encodeToByteString()

internal fun <T : Any> supported(value: T?): Outcome<T, AcmeFailure> =
    value?.let { found -> Outcome.Success(found) } ?: Outcome.Failure(AcmeError.Unsupported)

private fun mistyped(): Nothing = refuse(AcmeError.Malformed)
