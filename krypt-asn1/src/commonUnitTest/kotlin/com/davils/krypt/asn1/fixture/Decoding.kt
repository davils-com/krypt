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

package com.davils.krypt.asn1.fixture

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerLimits
import com.davils.krypt.asn1.DerReader

internal fun <T> decoded(text: String, limits: DerLimits = DerLimits.Default, block: DerReader.() -> T): T? =
    Der.decode(bytes = hex(text), limits = limits, block = block).getOrNull()

internal fun <T> refusal(text: String, limits: DerLimits = DerLimits.Default, block: DerReader.() -> T): DerFailure? {
    val outcome: Outcome<T, DerFailure> = Der.decode(bytes = hex(text), limits = limits, block = block)
    return outcome.failureOrNull()
}
