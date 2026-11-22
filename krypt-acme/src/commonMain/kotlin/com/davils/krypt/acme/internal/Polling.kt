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
import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.jose.JsonValue
import kotlin.time.Duration

internal object Polling {
    const val MAXIMUM_POLLS: Int = 1_000
    private const val TYPE: String = "type"
    private const val VALUE: String = "value"

    fun check(maximumPolls: Int, interval: Duration) {
        require(maximumPolls in 1..MAXIMUM_POLLS) { "A helper polls 1 to $MAXIMUM_POLLS times" }
        require(!interval.isNegative()) { "The interval is not negative" }
    }

    fun <T> settled(value: T, isWaiting: Boolean): Outcome<T, AcmeFailure> = when (isWaiting) {
        true -> Outcome.Failure(AcmeError.PollsExhausted)
        false -> Outcome.Success(value)
    }

    fun identifierOf(identifier: AcmeIdentifier): JsonValue.Object =
        JsonValue.Object.of(TYPE to text(identifier.type.typeName), VALUE to text(identifier.value))
}
