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

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.cose.CoseFailure

internal class CoseException(val failure: CoseFailure) : IllegalArgumentException(failure.name) {
    companion object {
        fun refuse(failure: CoseFailure): Nothing = throw CoseException(failure)

        fun ensure(condition: Boolean, failure: CoseFailure) {
            if (!condition) refuse(failure)
        }

        fun <T : Any> present(value: T?, failure: CoseFailure): T = value ?: refuse(failure)

        inline fun <T> outcome(block: () -> T): Outcome<T, CoseFailure> = try {
            Outcome.Success(block())
        } catch (refusal: CoseException) {
            Outcome.Failure(refusal.failure)
        }

        inline fun failureOf(block: () -> Unit): CoseFailure? = try {
            block()
            null
        } catch (refusal: CoseException) {
            refusal.failure
        }
    }
}
