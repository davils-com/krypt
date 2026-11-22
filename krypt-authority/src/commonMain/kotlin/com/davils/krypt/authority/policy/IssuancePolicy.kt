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
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.KeyFamily
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

/**
 * What a certificate authority may issue beyond its profiles: the longest validity, how far it backdates, which
 * names and keys it accepts and where its revocation information lies.
 *
 * Create it with [issuancePolicy]; [Default] permits every name and every signing key for 397 days at most.
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

        /**
         * Every name and every signing key, for 397 days at most and backdated five minutes.
         *
         * @since 1.0.0
         */
        public val Default: IssuancePolicy = issuancePolicy { }
    }
}
