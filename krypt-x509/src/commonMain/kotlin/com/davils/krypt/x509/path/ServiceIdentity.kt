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

import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.internal.IpAddresses
import com.davils.krypt.x509.name.GeneralName

private const val MAXIMUM_NAME: Int = 253
private const val MAXIMUM_LABEL: Int = 63
private const val WILDCARD: String = "*"
private const val MINIMUM_WILDCARD_LABELS: Int = 3

/**
 * Matches the identity of a service, such as the host a client connects to, against the subject alternative names of
 * its certificate by RFC 9525.
 *
 * A DNS name matches a DNS name of the certificate ignoring case, or a wildcard that stands for exactly the leftmost
 * label, such as `*.example.com` for `api.example.com` but neither `example.com` nor `a.api.example.com`; a wildcard
 * needs at least two labels after it. An IP address matches an IP address of the certificate byte for byte. The
 * common name is never consulted.
 *
 * @since 1.0.0
 */
public object ServiceIdentity {
    /**
     * Tells whether [certificate] identifies [host].
     *
     * @param certificate the certificate of the service.
     * @param host a DNS name in A-labels, an IPv4 address, or an IPv6 address with or without brackets.
     * @return true if a subject alternative name of [certificate] matches [host].
     * @since 1.0.0
     */
    public fun matches(certificate: Certificate, host: String): Boolean {
        val names = certificate.extensions.subjectAlternativeNames
        val address = IpAddresses.parseOrNull(host.removePrefix("[").removeSuffix("]"))
        val isIpMatch = address?.let { bytes ->
            names.any { name -> name is GeneralName.IpAddress && name.bytes == bytes }
        }
        val lower = host.lowercase()
        val reference = lower.removeSuffix(".").takeIf { found -> address == null && isDnsName(found) }
        val isDnsMatch = reference?.let { found ->
            names.any { name ->
                name is GeneralName.Dns &&
                    matchesDns(reference = found, presented = name.name)
            }
        }
        return isIpMatch == true || isDnsMatch == true
    }

    private fun matchesDns(reference: String, presented: String): Boolean {
        val pattern = presented.lowercase().removeSuffix(".")
        val labels = pattern.split('.')
        val isWildcard = labels.first() == WILDCARD && labels.size >= MINIMUM_WILDCARD_LABELS
        val rest = labels.drop(1).joinToString(".")
        val isWildcardMatch = isWildcard && reference.substringAfter('.', "") == rest && !reference.startsWith('.')
        val isExactMatch = !pattern.contains(WILDCARD) && pattern == reference
        return isWildcardMatch || isExactMatch
    }

    private fun isDnsName(name: String): Boolean {
        val labels = name.split('.')
        val isShort = name.length in 1..MAXIMUM_NAME
        return isShort && labels.all { label -> isLabel(label) }
    }

    private fun isLabel(label: String): Boolean {
        val isLength = label.length in 1..MAXIMUM_LABEL
        val isLdh = label.all { char -> char in 'a'..'z' || char in '0'..'9' || char == '-' }
        return isLength && isLdh && !label.startsWith('-') && !label.endsWith('-')
    }
}
