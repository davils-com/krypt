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

internal class PolicyState(
    private val parameters: ValidationParameters,
    length: Int,
    private val maximumNodes: Int,
) {
    private val root: PolicyNode = PolicyNode(policy = ANY, expected = setOf(ANY), parent = null)
    private var levels: List<List<PolicyNode>> = listOf(listOf(root))
    private var created: Int = 1
    private var isOverflowed: Boolean = false
    private var explicit: Int = counterOf(parameters.isExplicitPolicyRequired, length)
    private var mapping: Int = counterOf(parameters.isPolicyMappingInhibited, length)
    private var anyPolicy: Int = counterOf(parameters.isAnyPolicyInhibited, length)

    private val isTreeNull: Boolean get() = levels.isEmpty()

    fun process(certificate: Certificate, isLast: Boolean): Boolean {
        val policies = certificate.extensions.certificatePolicies?.takeUnless { isTreeNull }
        val isAnyAllowed = anyPolicy > 0 || (certificate.isSelfIssued && !isLast)
        levels = levels.takeUnless { policies == null }.orEmpty()
        policies?.let { asserted -> grow(policies = asserted, isAnyAllowed = isAnyAllowed) }
        return !isOverflowed && (explicit > 0 || !isTreeNull)
    }

    fun prepare(certificate: Certificate): Boolean {
        val mappings = certificate.extensions.policyMappings
        val isMappingValid = mappings.none { mapping -> mapping.issuerPolicy == ANY || mapping.subjectPolicy == ANY }
        if (isMappingValid && !isTreeNull) map(mappings)
        val step = listOf(1, 0)[certificate.isSelfIssued.compareTo(false)]
        explicit = (explicit - step).coerceAtLeast(0)
        mapping = (mapping - step).coerceAtLeast(0)
        anyPolicy = (anyPolicy - step).coerceAtLeast(0)
        val constraints = certificate.extensions.policyConstraints
        constraints?.requireExplicitPolicy?.let { skip -> explicit = minOf(a = explicit, b = skip) }
        constraints?.inhibitPolicyMapping?.let { skip -> mapping = minOf(a = mapping, b = skip) }
        certificate.extensions.inhibitAnyPolicy?.let { skip -> anyPolicy = minOf(a = anyPolicy, b = skip) }
        return isMappingValid && !isOverflowed
    }

    fun finish(leaf: Certificate): Set<ObjectIdentifier>? {
        explicit = (explicit - 1).coerceAtLeast(0)
        val isRequiredNow = leaf.extensions.policyConstraints?.requireExplicitPolicy == 0
        if (isRequiredNow) explicit = 0
        val initial = parameters.initialPolicies
        if (ANY !in initial && !isTreeNull) intersect(initial)
        val leaves = levels.lastOrNull().orEmpty()
        val policies = leaves.map { node -> node.policy }
        val isAcceptable = !isOverflowed && (explicit > 0 || !isTreeNull)
        return policies.toSet().takeIf { isAcceptable }
    }

    private fun grow(policies: List<ObjectIdentifier>, isAnyAllowed: Boolean) {
        val previous = levels.lastOrNull().orEmpty()
        val named = policies.distinct().filter { policy -> policy != ANY }
        val next = mutableListOf<PolicyNode>()
        named.forEach { policy ->
            val parents = previous.filter { node -> policy in node.expected }
            val chosen = parents.ifEmpty { previous.filter { node -> node.policy == ANY } }
            chosen.forEach { parent -> create(parent = parent, policy = policy, expected = setOf(policy), into = next) }
        }
        val isAnyAsserted = ANY in policies && isAnyAllowed
        previous.filter { isAnyAsserted }.forEach { parent -> expandAny(parent = parent, into = next) }
        levels = levels + listOf(next)
        prune()
    }

    private fun expandAny(parent: PolicyNode, into: MutableList<PolicyNode>) {
        val present = parent.children.map { child -> child.policy }.toSet()
        val missing = parent.expected.filter { policy -> policy !in present }
        missing.forEach { policy -> create(parent = parent, policy = policy, expected = setOf(policy), into = into) }
    }

    private fun map(mappings: List<PolicyMapping>) {
        val current = levels.last().toMutableList()
        val issuers = mappings.map { mapping -> mapping.issuerPolicy }.distinct()
        issuers.forEach { issuer ->
            val targets = mappings.filter { mapping -> mapping.issuerPolicy == issuer }
            val subjects = targets.map { mapping -> mapping.subjectPolicy }.toSet()
            val matching = current.filter { node -> node.policy == issuer }
            when (mapping > 0) {
                true -> remap(matching = matching, current = current, issuer = issuer, subjects = subjects)
                false -> matching.forEach { node -> node.detach() }
            }
        }
        levels = levels.dropLast(1) + listOf(current)
        prune()
    }

    private fun remap(
        matching: List<PolicyNode>,
        current: MutableList<PolicyNode>,
        issuer: ObjectIdentifier,
        subjects: Set<ObjectIdentifier>,
    ) {
        matching.forEach { node -> node.expected = subjects }
        val anyNodes = current.filter { node -> node.policy == ANY && matching.isEmpty() }
        val parents = anyNodes.mapNotNull { node -> node.parent }
        parents.forEach { parent -> create(parent = parent, policy = issuer, expected = subjects, into = current) }
    }

    private fun intersect(initial: Set<ObjectIdentifier>) {
        val all = levels.flatten()
        val validNodes = all.filter { node -> node.parent?.policy == ANY }
        val invalid = validNodes.filter { node -> node.policy != ANY && node.policy !in initial }
        invalid.forEach { node -> node.detach() }
        val deepest = levels.last().toMutableList()
        val anyLeaves = deepest.filter { node -> node.policy == ANY }
        val named = validNodes.map { node -> node.policy }.toSet()
        val missing = initial.filter { policy -> policy !in named }
        val parents = anyLeaves.mapNotNull { leaf -> leaf.parent }
        parents.forEach { parent ->
            missing.forEach { policy ->
                create(
                    parent = parent,
                    policy = policy,
                    expected = setOf(policy),
                    into = deepest,
                )
            }
        }
        anyLeaves.forEach { leaf -> leaf.detach() }
        prune()
    }

    private fun create(
        parent: PolicyNode,
        policy: ObjectIdentifier,
        expected: Set<ObjectIdentifier>,
        into: MutableList<PolicyNode>,
    ) {
        isOverflowed = isOverflowed || created >= maximumNodes
        if (!isOverflowed) {
            created += 1
            into += parent.adopt(policy = policy, expected = expected)
        }
    }

    private fun prune() {
        val depth = levels.size - 1
        val above = levels.dropLast(1).asReversed()
        above.forEach { level ->
            val childless = level.filter { node -> node.children.isEmpty() }
            childless.forEach { node -> node.detach() }
        }
        val rebuilt = (1..depth).runningFold(listOf(root)) { parents, _ -> parents.flatMap { node -> node.children } }
        levels = rebuilt.takeIf { found -> found.last().isNotEmpty() }.orEmpty()
    }

    private companion object {
        val ANY: ObjectIdentifier = KeyPurposes.AnyPolicy

        fun counterOf(isRequired: Boolean, length: Int): Int = listOf(length + 1, 0)[isRequired.compareTo(false)]
    }
}
