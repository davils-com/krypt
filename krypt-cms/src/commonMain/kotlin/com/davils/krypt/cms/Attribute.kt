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

package com.davils.krypt.cms

import com.davils.krypt.asn1.ObjectIdentifier
import kotlinx.io.bytestring.ByteString

/**
 * An attribute of CMS: a type and its values, each a complete DER element.
 *
 * krypt writes the values as a DER SET OF, sorted by their encodings.
 *
 * @property type the attribute type.
 * @param values the DER encodings of the values, at least one.
 * @constructor Holds an attribute.
 * @throws IllegalArgumentException if [values] is empty.
 * @since 1.0.0
 */
public class Attribute(public val type: ObjectIdentifier, values: List<ByteString>) {
    /**
     * The DER encodings of the values, at least one.
     *
     * @since 1.0.0
     */
    public val values: List<ByteString> = values.toList()

    init {
        require(this.values.isNotEmpty()) { "An attribute has at least one value" }
    }

    /**
     * Compares the type and the values.
     *
     * @param other the other object.
     * @return true if [other] is the same attribute.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is Attribute &&
        listOf(
            type,
            values,
        ) == listOf(other.type, other.values)

    /**
     * Hashes the type and the values.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(type, values).hashCode()

    /**
     * Shows the type and the number of values.
     *
     * @return the attribute as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Attribute(${type.dotted}, ${values.size} values)"
}
