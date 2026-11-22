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

import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.authority.profile.NameKind
import com.davils.krypt.x509.name.GeneralName
import kotlin.reflect.KClass

private const val WILDCARD: String = "*."

internal object NameRules {
    private val KINDS: Map<KClass<out GeneralName>, NameKind> = mapOf(
        GeneralName.Dns::class to NameKind.Dns,
        GeneralName.IpAddress::class to NameKind.IpAddress,
        GeneralName.Email::class to NameKind.Email,
        GeneralName.Uri::class to NameKind.Uri,
    )

    fun kindOf(name: GeneralName): NameKind? = KINDS[name::class]

    fun isPermitted(name: GeneralName, policy: IssuancePolicy): Boolean = when (kindOf(name)) {
        NameKind.Dns -> isDnsPermitted((name as GeneralName.Dns).name.lowercase(), policy)
        NameKind.IpAddress -> policy.isIpAddressAllowed
        NameKind.Email -> isEmailPermitted((name as GeneralName.Email).address.lowercase(), policy)
        NameKind.Uri -> isUriPermitted((name as GeneralName.Uri).uri, policy)
        null -> false
    }

    private fun isDnsPermitted(name: String, policy: IssuancePolicy): Boolean {
        val isWildcard = name.startsWith(WILDCARD)
        val base = name.removePrefix(WILDCARD)
        val isInDomain = policy.dnsDomains.isEmpty() || policy.dnsDomains.any { domain -> isWithin(base, domain) }
        return isInDomain && (!isWildcard || policy.isWildcardAllowed)
    }

    private fun isEmailPermitted(address: String, policy: IssuancePolicy): Boolean {
        val domain = address.substringAfterLast(delimiter = '@')
        return policy.emailDomains.isEmpty() || domain in policy.emailDomains
    }

    private fun isUriPermitted(uri: String, policy: IssuancePolicy): Boolean =
        policy.uriPrefixes.isEmpty() || policy.uriPrefixes.any { prefix -> uri.startsWith(prefix) }

    private fun isWithin(name: String, domain: String): Boolean = name == domain || name.endsWith(".$domain")
}
