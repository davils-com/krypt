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

package com.davils.krypt.authority.internal

import com.davils.krypt.authority.IssuanceFailure
import com.davils.krypt.authority.IssuanceRequest
import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.profile.NameKind
import com.davils.krypt.authority.profile.ProfileRule
import com.davils.krypt.x509.Certificate
import kotlin.time.Duration
import kotlin.time.Instant

internal class RequestChecks(private val authority: Certificate, private val policy: IssuancePolicy) {
    fun failureOf(request: IssuanceRequest, at: Instant): IssuanceFailure? = listOf(
        IssuanceFailure.KeyNotPermitted.takeUnless { request.publicKey.family in policy.keyFamilies },
        IssuanceFailure.InvalidRequest.takeIf { request.nameConstraints != null && !request.profile.isCa },
        IssuanceFailure.ProfileNotPermitted.takeUnless { isProfilePermitted(request) },
        IssuanceFailure.NameNotPermitted.takeUnless { areNamesPermitted(request) },
        IssuanceFailure.NameNotPermitted.takeUnless {
            SubjectRules.isPermitted(subject = request.subject, names = request.names, policy = policy)
        },
        IssuanceFailure.ValidityNotPermitted.takeUnless { isValidityPermitted(request, at) },
    ).firstOrNull { failure -> failure != null }

    fun validityOf(request: IssuanceRequest): Duration =
        request.validity ?: minOf(a = request.profile.maximumValidity, b = policy.maximumValidity)

    private fun isProfilePermitted(request: IssuanceRequest): Boolean {
        val limit = authority.extensions.basicConstraints?.pathLength
        val requested = request.profile.pathLength
        val isWithin = limit == null || (requested != null && requested < limit)
        return !request.profile.isCa || isWithin
    }

    private fun areNamesPermitted(request: IssuanceRequest): Boolean {
        val profile = request.profile
        val kinds = request.names.map { name -> NameRules.kindOf(name) }
        val areKindsAllowed = kinds.all { kind -> kind != null && kind in profile.nameKinds }
        val isPresent = !profile.isNameRequired || request.names.isNotEmpty()
        val isSingleUri = ProfileRule.SingleUri !in profile.rules || kinds == listOf(NameKind.Uri)
        val arePermitted = request.names.all { name -> NameRules.isPermitted(name, policy) }
        return areKindsAllowed && isPresent && isSingleUri && arePermitted
    }

    private fun isValidityPermitted(request: IssuanceRequest, at: Instant): Boolean {
        val validity = validityOf(request)
        val isWithinMaximum = validity <= request.profile.maximumValidity && validity <= policy.maximumValidity
        val isAuthorityValid = authority.isValidAt(at) && at + validity <= authority.notAfter
        return validity.isPositive() && isWithinMaximum && isAuthorityValid
    }
}
