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

package com.davils.krypt.cms.signed

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.krypt.cms.Attribute
import kotlin.time.Instant

/**
 * The options of one signer or countersigner.
 *
 * By default a signer is named by issuer and serial number, its certificate travels in the message and it signs the
 * signed attributes content-type (not for a countersignature), message-digest, signing-time from the clock of the
 * environment and the ESS signing-certificate-v2 of RFC 5035 with SHA-256. Ed448 signs without signed attributes,
 * because krypt has no SHAKE256 for the digest that RFC 8419 prescribes.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class SignerBuilder internal constructor() {
    internal val signedAttributes: MutableList<Attribute> = mutableListOf()

    internal val unsignedAttributes: MutableList<Attribute> = mutableListOf()

    /**
     * True to name the certificate by its subject key identifier, which it must carry, instead of issuer and serial.
     *
     * @since 1.0.0
     */
    public var isKeyIdentifierUsed: Boolean = false

    /**
     * True to carry the signer's certificate in the message.
     *
     * @since 1.0.0
     */
    public var isCertificateIncluded: Boolean = true

    /**
     * False to sign the content directly, without signed attributes; required for Ed448. Only content of type id-data
     * may be signed so, since RFC 5652 section 5.3 authenticates any other content type as a signed attribute.
     *
     * @since 1.0.0
     */
    public var isSignedAttributesUsed: Boolean = true

    /**
     * True to sign the ESS signing-certificate-v2 attribute, which binds the signature to the signer's certificate.
     *
     * @since 1.0.0
     */
    public var isSigningCertificateIncluded: Boolean = true

    /**
     * True to sign the signing-time attribute.
     *
     * @since 1.0.0
     */
    public var isSigningTimeIncluded: Boolean = true

    /**
     * The signing time, or null for the clock of the environment.
     *
     * @since 1.0.0
     */
    public var signingTime: Instant? = null

    /**
     * Adds a signed attribute of a type krypt does not write itself.
     *
     * @param attribute the attribute.
     * @since 1.0.0
     */
    public fun signedAttribute(attribute: Attribute) {
        signedAttributes += attribute
    }

    /**
     * Adds an unsigned attribute, such as a time-stamp token that was obtained before.
     *
     * @param attribute the attribute.
     * @since 1.0.0
     */
    public fun unsignedAttribute(attribute: Attribute) {
        unsignedAttributes += attribute
    }
}
