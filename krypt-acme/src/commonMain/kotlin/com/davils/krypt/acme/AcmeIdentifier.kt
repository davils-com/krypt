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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.acme

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.acme.internal.DnsNames
import com.davils.krypt.x509.name.GeneralName

/**
 * An identifier a certificate is ordered for: a DNS name or an IP address.
 *
 * Values are immutable and safe to share between threads.
 *
 * @property type the type.
 * @property value the DNS name in letters, digits and hyphens, at most 253 characters, possibly starting with `*.`;
 *   or the IPv4 or IPv6 address in text.
 * @constructor Checks the value against its type.
 * @throws IllegalArgumentException if [value] is no DNS name or IP address of its type.
 * @since 1.0.0
 */
public class AcmeIdentifier(public val type: IdentifierType, public val value: String) {
    /**
     * Whether the identifier is a wildcard DNS name, such as `*.example.org`.
     *
     * @since 1.0.0
     */
    public val isWildcard: Boolean get() = type == IdentifierType.Dns && value.startsWith(DnsNames.WILDCARD)

    internal val generalName: GeneralName = requireNotNull(nameOf(type = type, value = value)) {
        "${SafeText.quoted(value)} is no ${type.typeName} identifier"
    }

    /**
     * Compares the type and the value, the value of a DNS name ignoring case.
     *
     * @param other the other object.
     * @return true if [other] is the same identifier.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is AcmeIdentifier && type == other.type && value.equals(other = other.value, ignoreCase = true)

    /**
     * Hashes the type and the value.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(type, value.lowercase()).hashCode()

    /**
     * Shows the type and the value, escaped.
     *
     * @return the identifier as text.
     * @since 1.0.0
     */
    override fun toString(): String = "${type.typeName}:${SafeText.text(value)}"

    /**
     * Builds identifiers.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the identifier of the DNS name [name].
         *
         * @param name the name, possibly a wildcard such as `*.example.org`.
         * @return the identifier.
         * @throws IllegalArgumentException if [name] is no DNS name.
         * @since 1.0.0
         */
        public fun dns(name: String): AcmeIdentifier = AcmeIdentifier(IdentifierType.Dns, name)

        /**
         * Returns the identifier of the IP address [address], by RFC 8738.
         *
         * @param address the IPv4 or IPv6 address in text.
         * @return the identifier.
         * @throws IllegalArgumentException if [address] is no IP address.
         * @since 1.0.0
         */
        public fun ip(address: String): AcmeIdentifier = AcmeIdentifier(IdentifierType.Ip, address)

        private fun nameOf(type: IdentifierType, value: String): GeneralName? = when (type) {
            IdentifierType.Dns -> GeneralName.Dns(value).takeIf { DnsNames.isValid(value) }
            IdentifierType.Ip -> GeneralName.IpAddress.parseOrNull(value)
        }
    }
}
