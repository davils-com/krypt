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

package com.davils.krypt.cose.cwt

/**
 * Builds a [CwtValidation].
 *
 * @param configure names the algorithms, at least one, and what else the CWT must satisfy.
 * @return the validation.
 * @throws com.davils.kore.core.validation.report.ValidationException if no algorithm is accepted or the skew is
 *   negative or above [CwtValidation.MAXIMUM_SKEW].
 * @since 1.0.0
 */
public fun cwtValidation(configure: CwtValidationBuilder.() -> Unit): CwtValidation {
    val builder = CwtValidationBuilder()
    builder.configure()
    return builder.build()
}
