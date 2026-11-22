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

package com.davils.krypt.jose.jwt

/**
 * Builds the claims of a token.
 *
 * @param configure the claims.
 * @return the claims.
 * @throws com.davils.kore.core.validation.report.ValidationException if the token would expire before it becomes valid.
 * @since 1.0.0
 */
public fun jwtClaims(configure: JwtClaimsBuilder.() -> Unit): JwtClaims {
    val builder = JwtClaimsBuilder()
    builder.configure()
    return builder.build()
}

/**
 * Builds a validator of tokens.
 *
 * @param configure the checks.
 * @return the validator.
 * @throws com.davils.kore.core.validation.report.ValidationException if the skew is negative or above a day, the
 *   maximum age is not positive, a signed token has no algorithm or an encrypted one no content encryption.
 * @since 1.0.0
 */
public fun jwtValidator(configure: JwtValidatorBuilder.() -> Unit): JwtValidator {
    val builder = JwtValidatorBuilder()
    builder.configure()
    return builder.build()
}
