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

package com.davils.krypt.x509.crl

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.x509.RevocationReason
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.name.DistinguishedName
import kotlin.time.Instant

/**
 * Describes a revocation list to issue.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class RevocationListBuilder internal constructor() {
    internal val extensionsBuilder: ExtensionsBuilder = ExtensionsBuilder()

    internal val revoked: MutableList<RevokedCertificate> = mutableListOf()

    internal val extensions: List<Extension> get() = extensionsBuilder.extensions.toList()

    /**
     * The name of the issuer; required.
     *
     * @since 1.0.0
     */
    public var issuer: DistinguishedName? = null

    /**
     * When the list is issued; required.
     *
     * @since 1.0.0
     */
    public var thisUpdate: Instant? = null

    /**
     * When the next list is due; required by RFC 5280.
     *
     * @since 1.0.0
     */
    public var nextUpdate: Instant? = null

    /**
     * The number of the list, which grows with every list of the issuer; required by RFC 5280.
     *
     * @since 1.0.0
     */
    public var number: DerInteger? = null

    /**
     * The number of the full list this delta list builds on, or null for a full list.
     *
     * @since 1.0.0
     */
    public var deltaOf: DerInteger? = null

    /**
     * The scope of the list, or null for every certificate of the issuer.
     *
     * @since 1.0.0
     */
    public var issuingDistributionPoint: IssuingDistributionPoint? = null

    /**
     * Adds a revoked certificate.
     *
     * @param serialNumber the serial number.
     * @param revokedAt when it was revoked.
     * @param reason why, or null.
     * @param invalidAt since when the key is compromised, or null.
     * @since 1.0.0
     */
    public fun revoke(
        serialNumber: DerInteger,
        revokedAt: Instant,
        reason: RevocationReason? = null,
        invalidAt: Instant? = null,
    ) {
        revoked += RevokedCertificate(
            serialNumber = serialNumber,
            revokedAt = revokedAt,
            reason = reason,
            invalidAt = invalidAt,
        )
    }

    /**
     * Adds further extensions of the list, such as its authority key identifier.
     *
     * @param block adds the extensions.
     * @since 1.0.0
     */
    public fun extensions(block: ExtensionsBuilder.() -> Unit) {
        extensionsBuilder.block()
    }
}
