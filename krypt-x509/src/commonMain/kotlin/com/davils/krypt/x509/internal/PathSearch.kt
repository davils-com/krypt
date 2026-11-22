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

import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.path.PathFailure
import com.davils.krypt.x509.path.PathValidation
import com.davils.krypt.x509.path.TrustAnchor

internal class PathSearch(
    private val anchors: List<TrustAnchor>,
    private val pool: List<Certificate>,
    private val limits: X509Limits,
) {
    private var attempts = 0
    private var closest: PathValidation.Invalid? = null
    private var closestLength = 0

    suspend fun search(
        leaf: Certificate,
        check: suspend (List<Certificate>, TrustAnchor) -> PathValidation,
    ): PathValidation {
        val trusted = anchors.firstOrNull { anchor -> anchor.certificate == leaf }
        val direct = trusted?.let { anchor ->
            PathValidation.Valid(
                path = listOf(leaf),
                anchor = anchor,
                policies = emptySet(),
            )
        }
        return direct ?: extend(
            listOf(leaf),
            check,
        ) ?: closest ?: PathValidation.Invalid(PathFailure.NoTrustedPath, leaf)
    }

    private suspend fun extend(
        path: List<Certificate>,
        check: suspend (List<Certificate>, TrustAnchor) -> PathValidation,
    ): PathValidation.Valid? {
        val last = path.last()
        val issuing = anchors.filter { anchor -> anchor.name == last.issuer }
        val direct = issuing.firstNotNullOfOrNull { anchor -> attempt(path, anchor, check) }
        val isGrowable = direct == null && path.size < limits.maximumPathLength
        val issuers = pool.filter { candidate -> isIssuerOf(candidate, last) && candidate !in path }
        val candidates = issuers.takeIf { isGrowable }
        return direct ?: candidates?.firstNotNullOfOrNull { issuer -> grown(path + issuer, check) }
    }

    private suspend fun grown(
        path: List<Certificate>,
        check: suspend (List<Certificate>, TrustAnchor) -> PathValidation,
    ): PathValidation.Valid? {
        val found = extend(path, check)
        return found.takeIf { hasBudget() }
    }

    private suspend fun attempt(
        path: List<Certificate>,
        anchor: TrustAnchor,
        check: suspend (List<Certificate>, TrustAnchor) -> PathValidation,
    ): PathValidation.Valid? {
        attempts++
        val result = check(path, anchor).takeIf { hasBudget() }
        val invalid = result as? PathValidation.Invalid
        if (invalid != null && path.size >= closestLength) {
            closest = invalid
            closestLength = path.size
        }
        return result as? PathValidation.Valid
    }

    private fun hasBudget(): Boolean = attempts <= limits.maximumPathAttempts

    private fun isIssuerOf(candidate: Certificate, child: Certificate): Boolean {
        val authorityKey = child.extensions.authorityKeyIdentifier?.keyIdentifier
        val subjectKey = candidate.extensions.subjectKeyIdentifier
        val isKeyMatching = authorityKey == null || subjectKey == null || authorityKey == subjectKey
        return candidate.subject == child.issuer && isKeyMatching
    }
}
