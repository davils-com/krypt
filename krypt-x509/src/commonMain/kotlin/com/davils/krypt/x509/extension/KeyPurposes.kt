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

package com.davils.krypt.x509.extension

import com.davils.krypt.asn1.ObjectIdentifier

/**
 * The key purposes of the extended key usage, the access methods and the policies krypt names.
 *
 * @since 1.0.0
 */
public object KeyPurposes {
    /**
     * TLS server authentication.
     *
     * @since 1.0.0
     */
    public val ServerAuth: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.3.1")

    /**
     * TLS client authentication.
     *
     * @since 1.0.0
     */
    public val ClientAuth: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.3.2")

    /**
     * Code signing.
     *
     * @since 1.0.0
     */
    public val CodeSigning: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.3.3")

    /**
     * E-mail protection.
     *
     * @since 1.0.0
     */
    public val EmailProtection: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.3.4")

    /**
     * Time stamping.
     *
     * @since 1.0.0
     */
    public val TimeStamping: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.3.8")

    /**
     * Signing OCSP responses.
     *
     * @since 1.0.0
     */
    public val OcspSigning: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.3.9")

    /**
     * Any purpose.
     *
     * @since 1.0.0
     */
    public val Any: ObjectIdentifier = ObjectIdentifier.of("2.5.29.37.0")

    /**
     * The access method of an OCSP responder.
     *
     * @since 1.0.0
     */
    public val OcspAccess: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.48.1")

    /**
     * The access method of the certificates of the issuer.
     *
     * @since 1.0.0
     */
    public val CaIssuersAccess: ObjectIdentifier = ObjectIdentifier.of("1.3.6.1.5.5.7.48.2")

    /**
     * The policy anyPolicy.
     *
     * @since 1.0.0
     */
    public val AnyPolicy: ObjectIdentifier = ObjectIdentifier.of("2.5.29.32.0")
}
