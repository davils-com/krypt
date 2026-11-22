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
import kotlinx.io.bytestring.ByteString

internal class PathSearch(
    private val anchors: List<TrustAnchor>,
    private val pool: List<Certificate>,
    private val limits: X509Limits,
    private val budget: PathBudget,
) {
    private var closest: PathValidation.Invalid? = null
    private var closestLength = 0

    suspend fun search(leaf: Certificate, check: PathCheck): PathValidation {
        val trusted = anchors.firstOrNull { anchor -> anchor.certificate == leaf }
        val direct = trusted?.let { anchor -> check.checkAnchored(leaf, anchor) }
        record(result = direct, length = 1)
        return direct as? PathValidation.Valid
            ?: extend(listOf(leaf), check)
            ?: closest
            ?: PathValidation.Invalid(PathRefusal(PathFailure.NoTrustedPath, leaf))
    }

    private suspend fun extend(path: List<Certificate>, check: PathCheck): PathValidation.Valid? {
        val last = path.last()
        val issuing = anchors.filter { anchor -> anchor.name == last.issuer }
        val direct = issuing.firstNotNullOfOrNull { anchor -> attempt(path = path, anchor = anchor, check = check) }
        val isGrowable = direct == null && path.size < limits.maximumPathLength
        val issuers = candidatesOf(last).filter { candidate -> candidate !in path }
        val candidates = issuers.takeIf { isGrowable }.orEmpty()
        return direct ?: candidates.firstNotNullOfOrNull { issuer -> grown(path = path + issuer, check = check) }
    }

    private suspend fun grown(path: List<Certificate>, check: PathCheck): PathValidation.Valid? =
        when (budget.spend()) {
            true -> extend(path, check)
            false -> null
        }

    private suspend fun attempt(path: List<Certificate>, anchor: TrustAnchor, check: PathCheck): PathValidation.Valid? {
        val result = check.check(path, anchor)
        val counted = result.takeUnless { budget.isSpent }
        record(result = counted, length = path.size)
        return result as? PathValidation.Valid
    }

    private fun record(result: PathValidation?, length: Int) {
        val invalid = result as? PathValidation.Invalid
        if (invalid != null && length >= closestLength) {
            closest = invalid
            closestLength = length
        }
    }

    private fun candidatesOf(child: Certificate): List<Certificate> {
        val authorityKey = child.extensions.authorityKeyIdentifier?.keyIdentifier
        val issuers = pool.filter { candidate -> isIssuerOf(candidate = candidate, child = child, key = authorityKey) }
        val matching = issuers.filter { candidate -> candidate.extensions.subjectKeyIdentifier == authorityKey }
        val named = matching.takeIf { authorityKey != null }.orEmpty()
        return named + issuers.filter { candidate -> candidate !in named }
    }

    private fun isIssuerOf(candidate: Certificate, child: Certificate, key: ByteString?): Boolean {
        val subjectKey = candidate.extensions.subjectKeyIdentifier
        val isKeyMatching = key == null || subjectKey == null || key == subjectKey
        return candidate.subject == child.issuer && isKeyMatching
    }
}
