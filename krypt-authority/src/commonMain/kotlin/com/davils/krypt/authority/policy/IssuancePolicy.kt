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

package com.davils.krypt.authority.policy

import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.inRange
import com.davils.kore.core.validation.positive
import com.davils.kore.core.validation.validateOrThrow
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.x509.name.AttributeTypes
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

private const val SUBJECT: String = "issuancePolicy"

/**
 * What a certificate authority may issue beyond its profiles: the longest validity, how far it backdates, which
 * names and keys it accepts and where its revocation information lies.
 *
 * Create it with [issuancePolicy]; [Default] permits every name and every signing key for 397 days at most.
 *
 * The subject of a certificate is held to the policy as well as its alternative names: it may hold only attributes of
 * [subjectAttributes], never an email address (which belongs into the alternative names), an attribute of
 * [fixedAttributes] only with its fixed value, and a common name only if it equals one of the alternative names of
 * the certificate or, for a certificate without alternative names, if it passes the rules of its kind: a common name
 * with `://` is checked as a URI, one with `@` as an email address and one with a dot and no white space as a DNS
 * name; any other common name, such as the name of a person or of a code signer, is accepted.
 *
 * DNS names must be names in A-labels of letters, digits and hyphens, with labels of 1 to 63 characters and at most
 * 253 characters in all; a wildcard is only a whole leftmost label `*` followed by at least two labels. A URI prefix
 * matches a URI that equals it or continues it at a `/`.
 *
 * @since 1.0.0
 */
public class IssuancePolicy internal constructor(builder: IssuancePolicyBuilder) : Validatable {
    /**
     * The longest validity of a certificate; profiles may allow less.
     *
     * @since 1.0.0
     */
    public val maximumValidity: Duration = builder.maximumValidity

    /**
     * How far the start of a validity lies before the issuance, to bear clocks that run late; at most a day.
     *
     * @since 1.0.0
     */
    public val backdate: Duration = builder.backdate

    /**
     * The DNS domains a DNS name must lie in, or none for any; a domain permits itself and its subdomains.
     *
     * @since 1.0.0
     */
    public val dnsDomains: List<String> = builder.dnsDomains.toList()

    /**
     * Whether a DNS name may be a wildcard such as `*.example.com`.
     *
     * @since 1.0.0
     */
    public val isWildcardAllowed: Boolean = builder.isWildcardAllowed

    /**
     * Whether a certificate may name IP addresses.
     *
     * @since 1.0.0
     */
    public val isIpAddressAllowed: Boolean = builder.isIpAddressAllowed

    /**
     * The domains an email address must lie in, or none for any; a domain permits only itself.
     *
     * @since 1.0.0
     */
    public val emailDomains: List<String> = builder.emailDomains.toList()

    /**
     * The prefixes a URI must start with, such as `spiffe://example.org/`, or none for any.
     *
     * @since 1.0.0
     */
    public val uriPrefixes: List<String> = builder.uriPrefixes.toList()

    /**
     * The key families a subject may have.
     *
     * @since 1.0.0
     */
    public val keyFamilies: Set<KeyFamily> = builder.keyFamilies.toSet()

    /**
     * The URLs of the revocation lists, written to every certificate.
     *
     * @since 1.0.0
     */
    public val crlUrls: List<String> = builder.crlUrls.toList()

    /**
     * The URLs of the OCSP responders, written to every certificate.
     *
     * @since 1.0.0
     */
    public val ocspUrls: List<String> = builder.ocspUrls.toList()

    /**
     * The URLs of the certificate of the authority, written to every certificate.
     *
     * @since 1.0.0
     */
    public val issuerUrls: List<String> = builder.issuerUrls.toList()

    /**
     * The certificate policies written to every certificate.
     *
     * @since 1.0.0
     */
    public val policies: List<ObjectIdentifier> = builder.policies.toList()

    /**
     * The attribute types the subject may hold; by default the common name, the organization and its unit, the
     * country, the state, the locality and the serial number. An email address is refused whatever this says.
     *
     * @since 1.0.0
     */
    public val subjectAttributes: Set<ObjectIdentifier> = builder.subjectAttributes.toSet()

    /**
     * The values attributes of the subject must have when they are present, such as `O` = `Example Ltd`.
     *
     * @since 1.0.0
     */
    public val fixedAttributes: Map<ObjectIdentifier, String> = builder.fixedAttributes.toMap()

    init {
        validateOrThrow(SUBJECT)
    }

    /**
     * Checks that the validity is positive and the backdate lies between zero and a day.
     *
     * @receiver the validation that collects the violations.
     * @since 1.0.0
     */
    override fun ValidationScope.validate() {
        positive(property = ::maximumValidity, value = maximumValidity)
        inRange(property = ::backdate, value = backdate, range = Duration.ZERO..MAXIMUM_BACKDATE)
    }

    /**
     * Shows the validity and the restrictions.
     *
     * @return the policy as text.
     * @since 1.0.0
     */
    override fun toString(): String = "IssuancePolicy(maximumValidity=$maximumValidity, backdate=$backdate, " +
        "dnsDomains=${dnsDomains.size}, keyFamilies=$keyFamilies)"

    /**
     * The default policy.
     *
     * @since 1.0.0
     */
    public companion object {
        internal val MAXIMUM_BACKDATE: Duration = 1.days

        internal val DEFAULT_BACKDATE: Duration = 5.minutes

        internal const val DEFAULT_DAYS: Int = 397

        internal val DEFAULT_ATTRIBUTES: Set<ObjectIdentifier> = setOf(
            AttributeTypes.CommonName,
            AttributeTypes.Organization,
            AttributeTypes.OrganizationalUnit,
            AttributeTypes.Country,
            AttributeTypes.State,
            AttributeTypes.Locality,
            AttributeTypes.SerialNumber,
        )

        /**
         * Every name and every signing key, for 397 days at most and backdated five minutes.
         *
         * @since 1.0.0
         */
        public val Default: IssuancePolicy = issuancePolicy { }
    }
}
