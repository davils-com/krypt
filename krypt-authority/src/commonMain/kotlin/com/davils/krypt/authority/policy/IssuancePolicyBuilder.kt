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

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.dsl.ValidatingBuilder
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.KeyFamily
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * Configures an [IssuancePolicy]; see its properties for the meaning of each setting.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class IssuancePolicyBuilder internal constructor() : ValidatingBuilder<IssuancePolicy>() {
    override val subject: String get() = "issuancePolicy"

    internal val dnsDomains: MutableList<String> = mutableListOf()

    internal val emailDomains: MutableList<String> = mutableListOf()

    internal val uriPrefixes: MutableList<String> = mutableListOf()

    internal val keyFamilies: MutableSet<KeyFamily> =
        mutableSetOf(KeyFamily.Ec, KeyFamily.Rsa, KeyFamily.Ed25519, KeyFamily.Ed448, KeyFamily.MlDsa)

    internal val crlUrls: MutableList<String> = mutableListOf()

    internal val ocspUrls: MutableList<String> = mutableListOf()

    internal val issuerUrls: MutableList<String> = mutableListOf()

    internal val policies: MutableList<ObjectIdentifier> = mutableListOf()

    /**
     * See [IssuancePolicy.maximumValidity]; 397 days by default.
     *
     * @since 1.0.0
     */
    public var maximumValidity: Duration = IssuancePolicy.DEFAULT_DAYS.days
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [IssuancePolicy.backdate]; five minutes by default.
     *
     * @since 1.0.0
     */
    public var backdate: Duration = IssuancePolicy.DEFAULT_BACKDATE
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [IssuancePolicy.isWildcardAllowed]; false by default.
     *
     * @since 1.0.0
     */
    public var isWildcardAllowed: Boolean = false
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * See [IssuancePolicy.isIpAddressAllowed]; true by default.
     *
     * @since 1.0.0
     */
    public var isIpAddressAllowed: Boolean = true
        set(value) {
            checkOpen()
            field = value
        }

    /**
     * Permits DNS names in [domains] and their subdomains only.
     *
     * @param domains the domains, such as `example.com`.
     * @since 1.0.0
     */
    public fun dnsDomains(vararg domains: String) {
        checkOpen()
        dnsDomains += domains.map { domain -> domain.lowercase() }
    }

    /**
     * Permits email addresses in [domains] only.
     *
     * @param domains the domains, such as `example.com`.
     * @since 1.0.0
     */
    public fun emailDomains(vararg domains: String) {
        checkOpen()
        emailDomains += domains.map { domain -> domain.lowercase() }
    }

    /**
     * Permits URIs that start with one of [prefixes] only.
     *
     * @param prefixes the prefixes, such as `spiffe://example.org/`.
     * @since 1.0.0
     */
    public fun uriPrefixes(vararg prefixes: String) {
        checkOpen()
        uriPrefixes += prefixes
    }

    /**
     * Permits subjects with keys of [families] only.
     *
     * @param families the key families.
     * @since 1.0.0
     */
    public fun keyFamilies(vararg families: KeyFamily) {
        checkOpen()
        keyFamilies.clear()
        keyFamilies += families
    }

    /**
     * Writes the URLs of the revocation lists to every certificate.
     *
     * @param urls the URLs.
     * @since 1.0.0
     */
    public fun crlUrls(vararg urls: String) {
        checkOpen()
        crlUrls += urls
    }

    /**
     * Writes the URLs of the OCSP responders to every certificate.
     *
     * @param urls the URLs.
     * @since 1.0.0
     */
    public fun ocspUrls(vararg urls: String) {
        checkOpen()
        ocspUrls += urls
    }

    /**
     * Writes the URLs of the certificate of the authority to every certificate.
     *
     * @param urls the URLs.
     * @since 1.0.0
     */
    public fun issuerUrls(vararg urls: String) {
        checkOpen()
        issuerUrls += urls
    }

    /**
     * Writes certificate policies to every certificate.
     *
     * @param ids the policy identifiers.
     * @since 1.0.0
     */
    public fun policies(vararg ids: ObjectIdentifier) {
        checkOpen()
        policies += ids
    }

    override fun assemble(): IssuancePolicy = IssuancePolicy(this)
}

/**
 * Creates an [IssuancePolicy].
 *
 * @param configure configures the policy.
 * @return the policy.
 * @throws com.davils.kore.core.validation.report.ValidationException if a setting is out of range.
 * @since 1.0.0
 */
public fun issuancePolicy(configure: IssuancePolicyBuilder.() -> Unit): IssuancePolicy {
    val builder = IssuancePolicyBuilder()
    builder.configure()
    return builder.build()
}
