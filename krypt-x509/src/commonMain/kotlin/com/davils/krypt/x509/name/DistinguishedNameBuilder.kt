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

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.krypt.asn1.ObjectIdentifier

/**
 * Builds a [DistinguishedName], most significant relative name first, such as country, organization and common name.
 *
 * A country and a serial number are encoded as PrintableString, a domain component and an e-mail address as
 * IA5String, every other value as UTF8String.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class DistinguishedNameBuilder internal constructor() {
    internal val names: MutableList<List<Pair<ObjectIdentifier, String>>> = mutableListOf()

    /**
     * Adds a relative name of one attribute.
     *
     * @param type the attribute type.
     * @param value the value.
     * @throws IllegalArgumentException if [value] is empty or longer than 1024 characters.
     * @since 1.0.0
     */
    public fun attribute(type: ObjectIdentifier, value: String) {
        multiValued(listOf(type to value))
    }

    /**
     * Adds a multi-valued relative name.
     *
     * @param attributes the attributes; at least one.
     * @throws IllegalArgumentException if [attributes] is empty or a value is invalid.
     * @since 1.0.0
     */
    public fun multiValued(attributes: List<Pair<ObjectIdentifier, String>>) {
        require(attributes.isNotEmpty()) { "A relative name has at least one attribute" }
        require(attributes.all { (_, value) -> value.length in 1..MAXIMUM_VALUE }) {
            "A value of a name has 1 to $MAXIMUM_VALUE characters"
        }
        names += attributes.toList()
    }

    /**
     * Adds the common name.
     *
     * @param value the value.
     * @since 1.0.0
     */
    public fun commonName(value: String) {
        attribute(AttributeTypes.CommonName, value)
    }

    /**
     * Adds the country.
     *
     * @param value the two-letter code.
     * @throws IllegalArgumentException if [value] is not two letters.
     * @since 1.0.0
     */
    public fun country(value: String) {
        require(value.length == 2 && value.all { char -> char in 'A'..'Z' }) { "A country is two upper case letters" }
        attribute(AttributeTypes.Country, value)
    }

    /**
     * Adds the organization.
     *
     * @param value the value.
     * @since 1.0.0
     */
    public fun organization(value: String) {
        attribute(AttributeTypes.Organization, value)
    }

    /**
     * Adds an organizational unit.
     *
     * @param value the value.
     * @since 1.0.0
     */
    public fun organizationalUnit(value: String) {
        attribute(AttributeTypes.OrganizationalUnit, value)
    }

    /**
     * Adds a domain component.
     *
     * @param value the value.
     * @since 1.0.0
     */
    public fun domainComponent(value: String) {
        attribute(AttributeTypes.DomainComponent, value)
    }

    private companion object {
        const val MAXIMUM_VALUE: Int = 1_024
    }
}
