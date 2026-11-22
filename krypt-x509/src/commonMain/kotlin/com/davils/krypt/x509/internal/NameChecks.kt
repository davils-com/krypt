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
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.name.AttributeTypes
import com.davils.krypt.x509.name.GeneralName

private const val SCHEME: String = "://"
private const val WILDCARD: String = "*."
private val HOST_ENDS: CharArray = charArrayOf('/', '?', '#')

internal object NameChecks {
    fun isPermitted(certificate: Certificate, constraints: List<NameConstraints>): Boolean {
        val names = namesOf(certificate)
        return constraints.all { constraint -> names.all { name -> isWithin(name, constraint) } }
    }

    fun namesOf(certificate: Certificate): List<GeneralName> {
        val subject = certificate.subject
        val directories = listOf(GeneralName.Directory(subject))
        val directory = directories.takeUnless { subject.isEmpty }.orEmpty()
        val emails = subject.valuesOf(AttributeTypes.EmailAddress).map { address -> GeneralName.Email(address) }
        return certificate.extensions.subjectAlternativeNames + directory + emails
    }

    fun dnsMatches(name: String, base: String): Boolean {
        val host = hostOf(name)
        val domain = hostOf(base)
        val isSubdomainOnly = domain.startsWith('.')
        val isExact = host == domain && !isSubdomainOnly
        val isBelow = host.endsWith(listOf(".$domain", domain)[isSubdomainOnly.compareTo(false)])
        return domain.isEmpty() || isExact || isBelow
    }

    private fun hostOf(name: String): String = name.lowercase().trimEnd('.')

    private fun isWithin(name: GeneralName, constraint: NameConstraints): Boolean {
        val permitted = constraint.permitted.filter { base -> base::class == name::class }
        val isPermitted = permitted.isEmpty() || constraint.permitted.any { base -> covers(name, base) }
        val isExcluded = constraint.excluded.any { base -> touches(name, base) }
        return isPermitted && !isExcluded
    }

    private fun covers(name: GeneralName, base: GeneralName): Boolean {
        val scope = wildcardScopeOf(name)
        val domain = subtreeOf(base)
        val isScopeCovered = scope != null && domain != null && dnsMatches(name = scope, base = domain)
        return listOf(matches(name, base), isScopeCovered)[(scope != null).compareTo(false)]
    }

    private fun touches(name: GeneralName, base: GeneralName): Boolean {
        val scope = wildcardScopeOf(name)
        val domain = subtreeOf(base)
        val isHost = base is GeneralName.Dns && !base.name.startsWith('.')
        val parent = domain?.substringAfter(delimiter = '.', missingDelimiterValue = "")
        val isChildOfScope = isHost && parent == scope
        val isWithinScope = scope != null && domain != null && dnsMatches(name = scope, base = domain)
        val isScopeTouched = isWithinScope || isChildOfScope
        return matches(name, base) || isScopeTouched
    }

    private fun subtreeOf(base: GeneralName): String? {
        val dns = base as? GeneralName.Dns ?: return null
        return hostOf(dns.name).removePrefix(".")
    }

    private fun wildcardScopeOf(name: GeneralName): String? {
        val dns = name as? GeneralName.Dns ?: return null
        val host = hostOf(dns.name)
        return host.takeIf { found -> found.startsWith(WILDCARD) }?.removePrefix(WILDCARD)
    }

    private fun matches(name: GeneralName, base: GeneralName): Boolean = when (name) {
        is GeneralName.Dns -> base is GeneralName.Dns && dnsMatches(name = name.name, base = base.name)
        is GeneralName.Email -> base is GeneralName.Email && emailMatches(address = name.address, base = base.address)
        is GeneralName.Uri -> base is GeneralName.Uri && uriMatches(uri = name.uri, base = base.uri)
        is GeneralName.IpAddress -> base is GeneralName.IpAddress && ipMatches(name, base)
        is GeneralName.Directory -> base is GeneralName.Directory && base.name.isPrefixOf(name.name)
        is GeneralName.RegisteredId -> name == base
        is GeneralName.Other -> name == base
    }

    private fun emailMatches(address: String, base: String): Boolean {
        val host = address.substringAfterLast('@').lowercase()
        val domain = base.lowercase()
        val isMailbox = '@' in base
        val isDomainMatch = host == domain || (domain.startsWith('.') && host.endsWith(domain))
        return listOf(isDomainMatch, GeneralName.Email(address) == GeneralName.Email(base))[isMailbox.compareTo(false)]
    }

    private fun uriMatches(uri: String, base: String): Boolean {
        val authority = uri.substringAfter(delimiter = SCHEME, missingDelimiterValue = "").substringBefore(HOST_ENDS)
        val hostAndPort = authority.substringAfterLast('@')
        val host = hostOf(hostAndPort.substringBeforeLast(':'))
        val isName = host.isNotEmpty() && !host.startsWith('[')
        val domain = hostOf(base)
        val isMatch = listOf(host == domain, host.endsWith(domain))[domain.startsWith('.').compareTo(false)]
        return isName && isMatch
    }

    private fun ipMatches(name: GeneralName.IpAddress, base: GeneralName.IpAddress): Boolean {
        val half = base.bytes.size / 2
        val isSameFamily = name.bytes.size == half
        return isSameFamily &&
            (0 until half).all { index ->
                val mask = base.bytes[half + index].toInt()
                name.bytes[index].toInt() and mask == base.bytes[index].toInt() and mask
            }
    }

    private fun String.substringBefore(delimiters: CharArray): String {
        val index = indexOfAny(delimiters)
        return listOf(this, substring(startIndex = 0, endIndex = index.coerceAtLeast(0)))[(index >= 0).compareTo(false)]
    }
}
