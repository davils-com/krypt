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

import com.davils.krypt.authority.IssuanceRequest
import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.profile.ProfileRule
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.x509.extension.AccessDescription
import com.davils.krypt.x509.extension.DistributionPoint
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.extension.KeyPurposes
import com.davils.krypt.x509.extension.KeyUsage
import com.davils.krypt.x509.name.GeneralName

internal class ProfileExtensions(private val request: IssuanceRequest, private val policy: IssuancePolicy) {
    fun write(builder: ExtensionsBuilder, ids: KeyIds) {
        val profile = request.profile
        builder.basicConstraints(isCa = profile.isCa, pathLength = profile.pathLength)
        builder.keyUsage(usages())
        if (profile.purposes.isNotEmpty()) {
            builder.extendedKeyUsage(profile.purposes, critical = ProfileRule.CriticalPurposes in profile.rules)
        }
        if (request.names.isNotEmpty()) {
            builder.subjectAlternativeNames(request.names, critical = request.subject.isEmpty)
        }
        builder.subjectKeyIdentifier(ids.subject)
        builder.authorityKeyIdentifier(ids.authority)
        request.nameConstraints?.let { constraints -> builder.nameConstraints(constraints) }
        writePolicy(builder)
        if (ProfileRule.MustStaple in profile.rules) builder.mustStaple()
        if (ProfileRule.OcspNoCheck in profile.rules) builder.ocspNoCheck()
    }

    private fun usages(): Set<KeyUsage> {
        val profile = request.profile
        val isRsa = request.publicKey.family == KeyFamily.Rsa
        val isEncipherment = ProfileRule.RsaKeyEncipherment in profile.rules && isRsa
        val extra = setOfNotNull(KeyUsage.KeyEncipherment.takeIf { isEncipherment })
        return profile.keyUsages + extra
    }

    private fun writePolicy(builder: ExtensionsBuilder) {
        if (policy.policies.isNotEmpty()) builder.certificatePolicies(policy.policies)
        if (policy.crlUrls.isNotEmpty()) {
            val names = policy.crlUrls.map { url -> GeneralName.Uri(url) }
            builder.crlDistributionPoints(listOf(DistributionPoint(names)))
        }
        val access = policy.ocspUrls.map { url -> AccessDescription(KeyPurposes.OcspAccess, GeneralName.Uri(url)) } +
            policy.issuerUrls.map { url -> AccessDescription(KeyPurposes.CaIssuersAccess, GeneralName.Uri(url)) }
        if (access.isNotEmpty()) builder.authorityInformationAccess(access)
    }
}
