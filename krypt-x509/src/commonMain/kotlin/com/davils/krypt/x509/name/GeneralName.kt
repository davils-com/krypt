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

package com.davils.krypt.x509.name

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.x509.internal.IpAddresses
import kotlinx.io.bytestring.ByteString

/**
 * A general name of X.509, as in a subject alternative name or a name constraint.
 *
 * @since 1.0.0
 */
@OptIn(DavilsInternal::class)
public sealed interface GeneralName {
    /**
     * A DNS name, such as `www.example.com` or `*.example.com`; in a name constraint, a domain and its subdomains.
     *
     * @property name the name in A-labels.
     * @constructor Holds [name].
     * @since 1.0.0
     */
    public class Dns(public val name: String) : GeneralName {
        /**
         * Compares the name ignoring case.
         *
         * @param other the other object.
         * @return true if [other] is the same name.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Dns && name.lowercase() == other.name.lowercase()

        /**
         * Hashes the name in lower case.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = name.lowercase().hashCode()

        /**
         * Shows the name escaped.
         *
         * @return the name as text.
         * @since 1.0.0
         */
        override fun toString(): String = "DNS:${SafeText.text(name)}"
    }

    /**
     * An e-mail address of RFC 822; in a name constraint, also a host or a domain.
     *
     * @property address the address.
     * @constructor Holds [address].
     * @since 1.0.0
     */
    public class Email(public val address: String) : GeneralName {
        private val normalized: String
            get() = address.substringBeforeLast('@', "") + "@" + address.substringAfterLast('@').lowercase()

        /**
         * Compares the address, the domain ignoring case.
         *
         * @param other the other object.
         * @return true if [other] is the same address.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Email && normalized == other.normalized

        /**
         * Hashes the address.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = normalized.hashCode()

        /**
         * Shows the address escaped.
         *
         * @return the address as text.
         * @since 1.0.0
         */
        override fun toString(): String = "email:${SafeText.text(address)}"
    }

    /**
     * A uniform resource identifier, such as `spiffe://example.org/service`.
     *
     * @property uri the identifier.
     * @constructor Holds [uri].
     * @since 1.0.0
     */
    public class Uri(public val uri: String) : GeneralName {
        /**
         * Compares the identifier.
         *
         * @param other the other object.
         * @return true if [other] is the same identifier.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Uri && uri == other.uri

        /**
         * Hashes the identifier.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = uri.hashCode()

        /**
         * Shows the identifier escaped.
         *
         * @return the identifier as text.
         * @since 1.0.0
         */
        override fun toString(): String = "URI:${SafeText.text(uri)}"
    }

    /**
     * An IPv4 or IPv6 address of 4 or 16 bytes; in a name constraint, an address and a mask of 8 or 32 bytes.
     *
     * @property bytes the address, or the address followed by the mask.
     * @constructor Holds [bytes].
     * @throws IllegalArgumentException if [bytes] are not 4, 8, 16 or 32 bytes.
     * @since 1.0.0
     */
    public class IpAddress(public val bytes: ByteString) : GeneralName {
        init {
            require(bytes.size in IpAddresses.SIZES) { "An IP address has 4 or 16 bytes, with a mask 8 or 32" }
        }

        /**
         * Compares the bytes.
         *
         * @param other the other object.
         * @return true if [other] is the same address.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is IpAddress && bytes == other.bytes

        /**
         * Hashes the bytes.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = bytes.hashCode()

        /**
         * Shows the address.
         *
         * @return the address as text.
         * @since 1.0.0
         */
        override fun toString(): String = "IP:${IpAddresses.format(bytes)}"

        /**
         * Reading addresses from text.
         *
         * @since 1.0.0
         */
        public companion object {
            /**
             * Reads an IPv4 address in dotted decimal or an IPv6 address in the text form of RFC 5952.
             *
             * @param text the address.
             * @return the address, or null if [text] is not one.
             * @since 1.0.0
             */
            public fun parseOrNull(text: String): IpAddress? {
                val bytes = IpAddresses.parseOrNull(text) ?: return null
                return IpAddress(bytes)
            }
        }
    }

    /**
     * A distinguished name.
     *
     * @property name the name.
     * @constructor Holds [name].
     * @since 1.0.0
     */
    public class Directory(public val name: DistinguishedName) : GeneralName {
        /**
         * Compares the name by RFC 5280.
         *
         * @param other the other object.
         * @return true if [other] is the same name.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Directory && name == other.name

        /**
         * Hashes the name.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = name.hashCode()

        /**
         * Shows the name.
         *
         * @return the name as text.
         * @since 1.0.0
         */
        override fun toString(): String = "DirName:$name"
    }

    /**
     * A registered object identifier.
     *
     * @property id the identifier.
     * @constructor Holds [id].
     * @since 1.0.0
     */
    public class RegisteredId(public val id: ObjectIdentifier) : GeneralName {
        /**
         * Compares the identifier.
         *
         * @param other the other object.
         * @return true if [other] is the same identifier.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is RegisteredId && id == other.id

        /**
         * Hashes the identifier.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = id.hashCode()

        /**
         * Shows the identifier.
         *
         * @return the identifier as text.
         * @since 1.0.0
         */
        override fun toString(): String = "RID:${id.dotted}"
    }

    /**
     * A general name krypt keeps as it is: an other name, an X.400 address or an EDI party name.
     *
     * @property encoded the DER encoding with its context tag.
     * @since 1.0.0
     */
    public class Other internal constructor(public val encoded: ByteString) : GeneralName {
        /**
         * Compares the encoding.
         *
         * @param other the other object.
         * @return true if [other] has the same encoding.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Other && encoded == other.encoded

        /**
         * Hashes the encoding.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = encoded.hashCode()

        /**
         * Shows the encoding in hex.
         *
         * @return the name as text.
         * @since 1.0.0
         */
        override fun toString(): String = "other:${Hex.encode(encoded)}"
    }
}
