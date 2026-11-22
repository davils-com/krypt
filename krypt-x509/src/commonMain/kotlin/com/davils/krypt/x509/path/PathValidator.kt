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
import com.davils.krypt.x509.internal.PathCheck
import com.davils.krypt.x509.internal.PathSearch

/**
 * Builds and validates certificate paths by RFC 5280, section 6, from an end entity to one of [anchors].
 *
 * Building tries the certificates the peer sent in any order and follows several candidate issuers, within the
 * limits of path length and attempts, so a cross-signed or re-keyed authority is found. Validation checks every
 * signature against the crypto policy, the validity, the names, the basic constraints and path lengths, the key
 * usage, the extended key usage of the [ValidationParameters.purpose], the name constraints of the anchor and every
 * authority, the certificate policies, unknown critical extensions and, with a [revocation] checker, the revocation
 * status of every certificate. The policy tree of RFC 5280 is reduced to the set of valid policies, which accepts no
 * path the tree refuses.
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
     * @return the valid path, or the failure of the path that came closest to an anchor.
     * @since 1.0.0
     */
    public suspend fun validate(
        leaf: Certificate,
        intermediates: List<Certificate> = emptyList(),
        parameters: ValidationParameters = ValidationParameters(),
    ): PathValidation {
        val at = parameters.at ?: crypto.environment.clock.now()
        val check = PathCheck(crypto = crypto, revocation = revocation, parameters = parameters, at = at)
        val search = PathSearch(anchors = anchors, pool = intermediates, limits = limits)
        return search.search(leaf) { path, anchor -> check.check(path, anchor) }
    }

    /**
     * Shows the number of anchors.
     *
     * @return the validator as text.
     * @since 1.0.0
     */
    override fun toString(): String = "PathValidator(${anchors.size} anchors)"
}
