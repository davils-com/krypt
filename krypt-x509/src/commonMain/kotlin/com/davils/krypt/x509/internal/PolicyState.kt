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

package com.davils.krypt.x509.internal

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.PolicyMapping
import com.davils.krypt.x509.path.ValidationParameters

internal class PolicyState(private val parameters: ValidationParameters, length: Int) {
    private var valid: Set<ObjectIdentifier>? = setOf(ANY)
    private var explicit: Int = counterOf(parameters.isExplicitPolicyRequired, length)
    private var mapping: Int = counterOf(parameters.isPolicyMappingInhibited, length)
    private var anyPolicy: Int = counterOf(parameters.isAnyPolicyInhibited, length)

    fun process(certificate: Certificate, isLast: Boolean): Boolean {
        val policies = certificate.extensions.certificatePolicies?.toSet()
        val isAnyAllowed = anyPolicy > 0 || (certificate.isSelfIssued && !isLast)
        valid = policies?.let { found -> next(current = valid, policies = found, isAnyAllowed = isAnyAllowed) }
        return explicit > 0 || valid != null
    }

    fun prepare(certificate: Certificate): Boolean {
        val mappings = certificate.extensions.policyMappings
        val isMappingValid = mappings.none { mapping -> mapping.issuerPolicy == ANY || mapping.subjectPolicy == ANY }
        val issuers = mappings.map { mapping -> mapping.issuerPolicy }.toSet()
        val known = valid.orEmpty()
        val mapped = known.flatMap { policy -> targetsOf(policy, mappings) }.toSet()
        valid = listOf(valid?.minus(issuers), mapped)[(mapping > 0).compareTo(false)]?.ifEmpty { null }
        val step = listOf(1, 0)[certificate.isSelfIssued.compareTo(false)]
        explicit = (explicit - step).coerceAtLeast(0)
        mapping = (mapping - step).coerceAtLeast(0)
        anyPolicy = (anyPolicy - step).coerceAtLeast(0)
        val constraints = certificate.extensions.policyConstraints
        constraints?.requireExplicitPolicy?.let { skip -> explicit = minOf(a = explicit, b = skip) }
        constraints?.inhibitPolicyMapping?.let { skip -> mapping = minOf(a = mapping, b = skip) }
        certificate.extensions.inhibitAnyPolicy?.let { skip -> anyPolicy = minOf(a = anyPolicy, b = skip) }
        return isMappingValid
    }

    fun finish(leaf: Certificate): Set<ObjectIdentifier>? {
        explicit = (explicit - 1).coerceAtLeast(0)
        val isRequiredNow = leaf.extensions.policyConstraints?.requireExplicitPolicy == 0
        if (isRequiredNow) explicit = 0
        val initial = parameters.initialPolicies
        val current = valid.orEmpty()
        val constrained = when (ANY in current) {
            true -> initial
            false -> listOf(current intersect initial, current)[(ANY in initial).compareTo(false)]
        }
        return constrained.takeIf { found -> explicit > 0 || found.isNotEmpty() }
    }

    private fun targetsOf(policy: ObjectIdentifier, mappings: List<PolicyMapping>): List<ObjectIdentifier> {
        val targets = mappings.filter { mapping -> mapping.issuerPolicy == policy }
        return targets.map { mapping -> mapping.subjectPolicy }.ifEmpty { listOf(policy) }
    }

    private fun next(
        current: Set<ObjectIdentifier>?,
        policies: Set<ObjectIdentifier>,
        isAnyAllowed: Boolean,
    ): Set<ObjectIdentifier>? {
        val known = current ?: return null
        val named = policies.minus(ANY)
        val hasAny = ANY in policies && isAnyAllowed
        val kept = listOf(named, named + ANY)[hasAny.compareTo(false)]
        val retained = listOf(known intersect named, known)[hasAny.compareTo(false)]
        val result = listOf(retained, kept)[(ANY in known).compareTo(false)]
        return result.ifEmpty { null }
    }

    private companion object {
        val ANY: ObjectIdentifier = KeyPurposes.AnyPolicy

        fun counterOf(isRequired: Boolean, length: Int): Int = listOf(length + 1, 0)[isRequired.compareTo(false)]
    }
}
