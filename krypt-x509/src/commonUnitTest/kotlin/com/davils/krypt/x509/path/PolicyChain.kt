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

package com.davils.krypt.x509.path

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.fixture.Authority
import com.davils.krypt.x509.fixture.NOW
import com.davils.krypt.x509.fixture.crypto

internal class PolicyChain(val root: Authority, val authority: Authority, val leaf: Authority) {
    suspend fun validate(
        initial: Set<ObjectIdentifier> = setOf(KeyPurposes.AnyPolicy),
        isExplicit: Boolean = true,
        isMappingInhibited: Boolean = false,
        isAnyInhibited: Boolean = false,
        limits: X509Limits = X509Limits.Default,
    ): PathValidation {
        val validator = PathValidator(
            crypto = crypto,
            anchors = listOf(TrustAnchor.of(root.certificate)),
            limits = limits,
        )
        val parameters = ValidationParameters(
            at = NOW,
            initialPolicies = initial,
            isExplicitPolicyRequired = isExplicit,
            isPolicyMappingInhibited = isMappingInhibited,
            isAnyPolicyInhibited = isAnyInhibited,
        )
        return validator.validate(leaf.certificate, listOf(authority.certificate), parameters)
    }
}
