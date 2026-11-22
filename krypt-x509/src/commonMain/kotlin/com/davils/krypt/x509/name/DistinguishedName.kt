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
import com.davils.krypt.x509.internal.NameParts
import kotlinx.io.bytestring.ByteString

/**
 * A distinguished name of X.509, such as the subject or the issuer of a certificate.
 *
 * Names compare by RFC 5280: attribute by attribute, ignoring case and surplus white space in strings. The encoding is
 * kept as it was read, so a name is written back byte for byte.
 *
 * @property names the relative names, most significant first, as they are encoded.
 * @property encoded the DER encoding.
 * @since 1.0.0
 */
@OptIn(DavilsInternal::class)
public class DistinguishedName private constructor(
    public val names: List<RelativeName>,
    public val encoded: ByteString,
) {
    /**
     * Whether the name has no relative names.
     *
     * @since 1.0.0
     */
    public val isEmpty: Boolean get() = names.isEmpty()

    /**
     * The value of the last common name, or null.
     *
     * @since 1.0.0
     */
    public val commonName: String? get() = valuesOf(AttributeTypes.CommonName).lastOrNull()

    internal constructor(parts: NameParts) : this(parts.names, parts.encoded)

    /**
     * Returns the text values of [type], most significant first.
     *
     * @param type the attribute type.
     * @return the values.
     * @since 1.0.0
     */
    public fun valuesOf(type: ObjectIdentifier): List<String> {
        val attributes = names.flatMap { name -> name.attributes }
        return attributes.filter { attribute -> attribute.type == type }.mapNotNull { attribute -> attribute.text }
    }

    /**
     * Returns the name by RFC 4514, least significant first, without escaping for display.
     *
     * @return the name as a string of RFC 4514.
     * @since 1.0.0
     */
    public fun rfc4514(): String = names.reversed().joinToString(",") { name ->
        name.attributes.joinToString("+") { attribute -> attribute.rfc4514() }
    }

    /**
     * Tells whether [other] starts with this name, as the name constraints of RFC 5280 require.
     *
     * @param other the name that may lie below this one.
     * @return true if every relative name of this name equals the one of [other] at the same position.
     * @since 1.0.0
     */
    public fun isPrefixOf(other: DistinguishedName): Boolean =
        names.size <= other.names.size && names == other.names.subList(fromIndex = 0, toIndex = names.size)

    /**
     * Compares by RFC 5280.
     *
     * @param other the other object.
     * @return true if [other] is the same name.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is DistinguishedName && names == other.names

    /**
     * Hashes the relative names.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = names.hashCode()

    /**
     * Shows the name by RFC 4514, escaped for safe display.
     *
     * @return the name as text.
     * @since 1.0.0
     */
    override fun toString(): String = SafeText.text(rfc4514())

    /**
     * Creating names.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The empty name.
         *
         * @since 1.0.0
         */
        public val Empty: DistinguishedName = distinguishedName {}
    }
}
