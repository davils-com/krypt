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

package com.davils.krypt.core

import com.davils.kore.core.Limits
import com.davils.kore.core.arguments.conversion.ConversionException
import com.davils.kore.core.arguments.conversion.Converter
import com.davils.kore.core.arguments.conversion.Converters

private const val SECRET_REASON: String = "is not a secret, expected 1 to 65536 characters"

private val SECRET_TEXT: Converter<SecretText> = object : Converter<SecretText> {
    override val typeName: String = "secret"

    override fun convert(raw: String): SecretText {
        val isBounded = raw.isNotEmpty() && raw.length <= Limits.MAX_ARGUMENT_LENGTH
        if (!isBounded) throw ConversionException(SECRET_REASON)
        return SecretText.of(raw)
    }
}

/**
 * A converter that reads a [SecretText], such as a password or an API token, for the options of Kore, the environment
 * reads of Knot and the properties of Kontext, so the value is held as characters krypt can wipe instead of a
 * `String` passed on.
 *
 * The raw text must have 1 to [Limits.MAX_ARGUMENT_LENGTH] characters; a refused text gets a constant reason that never
 * repeats it, and the secret shows nothing of itself. The `String` the caller read cannot be wiped, so read it as late
 * as possible and drop it at once. Its type name is `secret`.
 *
 * @since 1.2.0
 */
public val Converters.secretText: Converter<SecretText> get() = SECRET_TEXT
