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

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.jose.JoseFailure

internal fun <T : Any> invariant(value: T?): T = value ?: error("An invariant of krypt-jose does not hold")

internal fun refuse(failure: JoseFailure): Nothing = throw JoseRefusal(failure)

internal fun refuseUnless(condition: Boolean, failure: JoseFailure) {
    if (!condition) refuse(failure)
}

internal fun failureOf(exception: IllegalArgumentException): JoseFailure {
    if (exception is JoseRefusal) return exception.failure
    return JoseFailure.Malformed
}

internal inline fun <T> decoding(block: () -> T): Outcome<T, JoseFailure> = try {
    Outcome.Success(block())
} catch (refusal: IllegalArgumentException) {
    Outcome.Failure(failureOf(refusal))
}

internal fun utf8OrNull(text: String): ByteArray? = try {
    text.encodeToByteArray(startIndex = 0, endIndex = text.length, throwOnInvalidSequence = true)
} catch (ignored: CharacterCodingException) {
    null
}

internal fun textOrNull(bytes: ByteArray): String? = try {
    bytes.decodeToString(startIndex = 0, endIndex = bytes.size, throwOnInvalidSequence = true)
} catch (ignored: CharacterCodingException) {
    null
}

internal fun <T> Outcome<T, JoseFailure>.orRefuse(): T = when (this) {
    is Outcome.Success -> value
    is Outcome.Failure -> refuse(failure)
}
