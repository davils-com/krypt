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

import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.jwt.JwtClaims
import com.davils.krypt.jose.jwt.JwtValidator
import kotlin.time.Instant

private const val APPLICATION: String = "application/"

internal object ClaimsCheck {
    fun typeFailure(expected: String?, actual: String?): JoseFailure? {
        val isMatching = expected == null || (actual != null && normalized(expected) == normalized(actual))
        return JoseFailure.WrongType.takeUnless { isMatching }
    }

    fun claimsFailure(claims: JwtClaims, validator: JwtValidator, now: Instant): JoseFailure? {
        val members = claims.members
        val implied = listOfNotNull(
            ClaimNames.EXPIRES_AT.takeIf { validator.isExpirationRequired },
            ClaimNames.ISSUED_AT.takeIf { validator.maximumAge != null },
        )
        val required = validator.requiredClaims + implied
        val isComplete = required.all { name -> name in members }
        return JoseFailure.MissingClaim.takeUnless { isComplete }
            ?: timeFailure(claims = claims, validator = validator, now = now)
            ?: JoseFailure.WrongIssuer.takeUnless { validator.issuer == null || validator.issuer == claims.issuer }
            ?: JoseFailure.WrongAudience.takeUnless { isAudienceRight(claims.audience, validator.audiences) }
    }

    private fun timeFailure(claims: JwtClaims, validator: JwtValidator, now: Instant): JoseFailure? {
        val skew = validator.clockSkew
        val expiresAt = claims.expiresAt
        val notBefore = claims.notBefore
        val issuedAt = claims.issuedAt
        val maximumAge = validator.maximumAge
        val isExpired = expiresAt != null && now >= expiresAt + skew
        val isTooOld = issuedAt != null && maximumAge != null && now > issuedAt + maximumAge + skew
        val isEarly = (notBefore != null && now + skew < notBefore) || (issuedAt != null && now + skew < issuedAt)
        return JoseFailure.Expired.takeIf { isExpired || isTooOld } ?: JoseFailure.NotYetValid.takeIf { isEarly }
    }

    private fun isAudienceRight(audience: List<String>, expected: Set<String>): Boolean = when (expected.isEmpty()) {
        true -> audience.isEmpty()
        false -> audience.any { name -> name in expected }
    }

    private fun normalized(type: String): String {
        val lower = type.lowercase()
        val short = lower.removePrefix(APPLICATION)
        return short.takeUnless { '/' in short } ?: lower
    }
}
