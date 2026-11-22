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

import com.davils.krypt.asn1.ObjectIdentifier

/**
 * The attribute types of distinguished names that krypt names in text, by RFC 4519 and RFC 5280.
 *
 * @since 1.0.0
 */
public object AttributeTypes {
    /**
     * `CN`, the common name.
     *
     * @since 1.0.0
     */
    public val CommonName: ObjectIdentifier = ObjectIdentifier.of("2.5.4.3")

    /**
     * `SERIALNUMBER`, the serial number of a subject.
     *
     * @since 1.0.0
     */
    public val SerialNumber: ObjectIdentifier = ObjectIdentifier.of("2.5.4.5")

    /**
     * `C`, the two-letter country code.
     *
     * @since 1.0.0
     */
    public val Country: ObjectIdentifier = ObjectIdentifier.of("2.5.4.6")

    /**
     * `L`, the locality.
     *
     * @since 1.0.0
     */
    public val Locality: ObjectIdentifier = ObjectIdentifier.of("2.5.4.7")

    /**
     * `ST`, the state or province.
     *
     * @since 1.0.0
     */
    public val State: ObjectIdentifier = ObjectIdentifier.of("2.5.4.8")

    /**
     * `STREET`, the street address.
     *
     * @since 1.0.0
     */
    public val Street: ObjectIdentifier = ObjectIdentifier.of("2.5.4.9")

    /**
     * `O`, the organization.
     *
     * @since 1.0.0
     */
    public val Organization: ObjectIdentifier = ObjectIdentifier.of("2.5.4.10")

    /**
     * `OU`, the organizational unit.
     *
     * @since 1.0.0
     */
    public val OrganizationalUnit: ObjectIdentifier = ObjectIdentifier.of("2.5.4.11")

    /**
     * `organizationIdentifier`, such as a VAT number.
     *
     * @since 1.0.0
     */
    public val OrganizationIdentifier: ObjectIdentifier = ObjectIdentifier.of("2.5.4.97")

    /**
     * `DC`, a component of a domain.
     *
     * @since 1.0.0
     */
    public val DomainComponent: ObjectIdentifier = ObjectIdentifier.of("0.9.2342.19200300.100.1.25")

    /**
     * `UID`, the user id.
     *
     * @since 1.0.0
     */
    public val UserId: ObjectIdentifier = ObjectIdentifier.of("0.9.2342.19200300.100.1.1")

    /**
     * `emailAddress`, deprecated in names in favour of the subject alternative name.
     *
     * @since 1.0.0
     */
    public val EmailAddress: ObjectIdentifier = ObjectIdentifier.of("1.2.840.113549.1.9.1")

    internal val SHORT_NAMES: Map<ObjectIdentifier, String> = mapOf(
        CommonName to "CN",
        SerialNumber to "SERIALNUMBER",
        Country to "C",
        Locality to "L",
        State to "ST",
        Street to "STREET",
        Organization to "O",
        OrganizationalUnit to "OU",
        OrganizationIdentifier to "organizationIdentifier",
        DomainComponent to "DC",
        UserId to "UID",
        EmailAddress to "emailAddress",
    )

    internal val IA5_TYPES: Set<ObjectIdentifier> = setOf(DomainComponent, EmailAddress)

    internal val PRINTABLE_TYPES: Set<ObjectIdentifier> = setOf(Country, SerialNumber)
}
