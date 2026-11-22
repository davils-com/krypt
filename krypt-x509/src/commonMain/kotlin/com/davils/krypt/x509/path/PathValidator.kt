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

import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.internal.PathBudget
import com.davils.krypt.x509.internal.PathCheck
import com.davils.krypt.x509.internal.PathRefusal
import com.davils.krypt.x509.internal.PathSearch

/**
 * Builds and validates certificate paths by RFC 5280, section 6, from an end entity to one of [anchors].
 *
 * Building tries the certificates the peer sent and follows several candidate issuers, so a cross-signed or re-keyed
 * authority is found. Duplicates are dropped, and the candidates for an issuer are tried in a fixed order: those whose
 * subject key identifier matches the authority key identifier of the certificate they issue first, then the others in
 * the order given. A certificate never appears twice on one path.
 *
 * The work is bounded, whatever the peer sends. A validation considers at most [X509Limits.maximumIntermediates]
 * distinct certificates and refuses more with [PathFailure.PathTooLong]. It spends at most
 * [X509Limits.maximumPathAttempts] units of work, where every candidate issuer, every signature verification and every
 * call of the [revocation] checker counts as one; when they are spent, the search stops and returns the failure of the
 * closest path or [PathFailure.NoTrustedPath]. In the worst case a validation therefore runs
 * [X509Limits.maximumPathAttempts] signature verifications and revocation checks together, plus name comparisons
 * proportional to that number times [X509Limits.maximumIntermediates].
 *
 * Validation checks every signature against the crypto policy, the validity, the names, the basic constraints and
 * path lengths, the key usage, the extended key usage of the [ValidationParameters.purpose] and the key usage it needs
 * (`serverAuth` needs digital signature, key encipherment or key agreement, `clientAuth` digital signature or key
 * agreement), the name constraints of the anchor and every authority, the certificate policies, unknown critical
 * extensions and, with a [revocation] checker, the revocation status of every certificate. A DNS name with a wildcard
 * stands for every name it can match: it is refused if an excluded subtree lies within its scope and permitted only if
 * its whole scope is. Certificate policies are processed with the valid policy tree of RFC 5280, section 6.1,
 * including the intersection with [ValidationParameters.initialPolicies] in the domain of the anchor; the tree holds
 * at most [X509Limits.maximumPolicyNodes] nodes, and a path whose tree would grow larger is refused with
 * [PathFailure.Policy]. The TLS feature extension (must-staple) is accepted as known but enforced by the TLS layer
 * that sees the stapled response, not here.
 *
 * An end entity that equals the certificate of an anchor is valid on its own, but only if it is valid at the time of
 * validation, allows the purpose and has the key usage the purpose needs.
 *
 * The [revocation] checker is foreign code: a failure it throws counts as an unknown status, and only the
 * cancellation of the calling coroutine passes through.
 *
 * The object holds no state between validations and is safe to share between threads.
 *
 * @property crypto the primitives and their policy.
 * @param anchors the trust anchors.
 * @param revocation the revocation checker, or null to check no revocation.
 * @property limits the limits of path building.
 * @constructor Validates paths to [anchors].
 * @since 1.0.0
 */
public class PathValidator(
    public val crypto: Crypto,
    anchors: List<TrustAnchor>,
    private val revocation: RevocationChecker? = null,
    public val limits: X509Limits = X509Limits.Default,
) {
    /**
     * The trust anchors.
     *
     * @since 1.0.0
     */
    public val anchors: List<TrustAnchor> = anchors.toList()

    /**
     * Validates a path from [leaf] to an anchor through [intermediates].
     *
     * @param leaf the end entity, or an authority to validate as the end of a path.
     * @param intermediates the certificates that may lie on the path, in any order, possibly from an attacker.
     * @param parameters what to check besides RFC 5280.
     * @return the valid path, or the failure of the path that came closest to an anchor; [PathFailure.PathTooLong] if
     *   [intermediates] holds more distinct certificates than [X509Limits.maximumIntermediates].
     * @since 1.0.0
     */
    public suspend fun validate(
        leaf: Certificate,
        intermediates: List<Certificate> = emptyList(),
        parameters: ValidationParameters = ValidationParameters(),
    ): PathValidation {
        val pool = intermediates.distinct().filter { certificate -> certificate != leaf }
        if (pool.size > limits.maximumIntermediates) {
            return PathValidation.Invalid(PathRefusal(PathFailure.PathTooLong, leaf))
        }
        val at = parameters.at ?: crypto.environment.clock.now()
        val budget = PathBudget(limits.maximumPathAttempts)
        val check = PathCheck(
            crypto = crypto,
            revocation = revocation,
            parameters = parameters,
            at = at,
            budget = budget,
            maximumPolicyNodes = limits.maximumPolicyNodes,
        )
        val search = PathSearch(anchors = anchors, pool = pool, limits = limits, budget = budget)
        return search.search(leaf, check)
    }

    /**
     * Shows the number of anchors.
     *
     * @return the validator as text.
     * @since 1.0.0
     */
    override fun toString(): String = "PathValidator(${anchors.size} anchors)"
}
