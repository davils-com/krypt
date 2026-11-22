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

import com.davils.krypt.x509.internal.RelativeNameParts

/**
 * One relative distinguished name: one attribute, or several for a multi-valued name such as `CN=Ada+UID=42`.
 *
 * @property attributes the attributes, in the order of their encoding.
 * @since 1.0.0
 */
public class RelativeName private constructor(public val attributes: List<AttributeValue>) {
    private val sorted: List<String>
        get() = attributes.map { attribute -> "${attribute.type.dotted}=${attribute.normalized}" }.sorted()

    internal constructor(parts: RelativeNameParts) : this(parts.attributes)

    /**
     * Compares the attributes as a set, by RFC 5280.
     *
     * @param other the other object.
     * @return true if [other] holds the same attributes.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is RelativeName && sorted == other.sorted

    /**
     * Hashes the attributes.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = sorted.hashCode()

    /**
     * Shows the attributes by RFC 4514, joined by `+`.
     *
     * @return the name as text.
     * @since 1.0.0
     */
    override fun toString(): String = attributes.joinToString("+")
}
