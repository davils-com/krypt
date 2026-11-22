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

package com.davils.krypt.tls.trust

import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.atMost
import com.davils.kore.core.validation.validateOrThrow
import com.davils.krypt.ocsp.OcspResponseSource
import com.davils.krypt.x509.X509Limits
import com.davils.krypt.x509.path.PinSet
import com.davils.krypt.x509.path.RevocationListSource
import com.davils.krypt.x509.path.TrustAnchor

private const val SUBJECT: String = "trust"

/**
 * Whom a TLS peer must chain to and what else its certificates must show, built by [TrustSettingsBuilder].
 *
 * The certificates of a peer are validated by krypt-x509 by RFC 5280 against the [anchors] and, only if
 * [isSystemIncluded], the anchors of the JDK as well; both together count when both are given. A path that ends in an
 * anchor of the JDK alone must in addition be accepted by the PKIX trust manager of the JDK, so that its distrust
 * policies, disabled algorithms and anchor constraints keep applying to its roots.
 *
 * @since 1.0.0
 */
public class TrustSettings internal constructor(builder: TrustSettingsBuilder) : Validatable {
    /**
     * The trust anchors of the application.
     *
     * @since 1.0.0
     */
    public val anchors: List<TrustAnchor> = builder.anchors.toList()

    /**
     * Whether the anchors of the JDK count, too. A root of the JDK that krypt cannot read or whose key the crypto
     * policy forbids is left out. A path to a root of the JDK must also pass the default PKIX trust manager of the JDK
     * for the same side, with `jdk.security.caDistrustPolicies`, `jdk.certpath.disabledAlgorithms` and the constraints
     * of the JDK on its anchors; a refusal of the JDK is [TrustFailure.NoTrustedPath].
     *
     * @since 1.0.0
     */
    public val isSystemIncluded: Boolean = builder.isSystemIncluded

    /**
     * The pins of which one must match a key on the validated path, or null for no pinning.
     *
     * @since 1.0.0
     */
    public val pins: PinSet? = builder.pins

    /**
     * How revocation is checked.
     *
     * @since 1.0.0
     */
    public val revocation: RevocationMode = builder.revocation

    /**
     * The source of OCSP responses when a peer staples none, or null.
     *
     * @since 1.0.0
     */
    public val ocspSource: OcspResponseSource? = builder.ocspSource

    /**
     * The source of revocation lists when OCSP gives no answer, or null.
     *
     * @since 1.0.0
     */
    public val revocationListSource: RevocationListSource? = builder.revocationListSource

    /**
     * The cache of revocation statuses, or null.
     *
     * @since 1.0.0
     */
    public val cache: RevocationCache? = builder.cache

    /**
     * Whether a certificate with the TLS feature status_request of RFC 7633 must come with a stapled OCSP response.
     *
     * @since 1.0.0
     */
    public val isMustStapleEnforced: Boolean = builder.isMustStapleEnforced

    /**
     * The Certificate Transparency a peer must show, or null.
     *
     * @since 1.0.0
     */
    public val transparency: TransparencyRequirement? = builder.transparency

    /**
     * The limits of path building.
     *
     * @since 1.0.0
     */
    public val limits: X509Limits = builder.limits

    init {
        validateOrThrow(SUBJECT)
    }

    override fun ValidationScope.validate() {
        atMost(property = ::anchors, value = anchors.size, maximum = HARD_MAXIMUM_ANCHORS)
    }

    /**
     * Shows the settings without the anchors themselves.
     *
     * @return the settings as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "TrustSettings(anchors=${anchors.size}, system=$isSystemIncluded, pins=${pins != null}, " +
            "revocation=$revocation, ocspSource=${ocspSource != null}, " +
            "revocationListSource=${revocationListSource != null}, cache=${cache != null}, " +
            "mustStaple=$isMustStapleEnforced, transparency=${transparency != null})"

    /**
     * The bounds of the settings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The most anchors of the application.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ANCHORS: Int = 4_096
    }
}
