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

package com.davils.krypt.x509

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.extension.Extension
import com.davils.krypt.x509.extension.ExtensionsBuilder
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.DistinguishedNameBuilder
import com.davils.krypt.x509.name.distinguishedName
import kotlin.time.Instant

/**
 * Describes a certificate to issue: its subject, its public key, its validity, its issuer and its extensions.
 *
 * The serial number is drawn from the randomness of the environment unless one is given: 20 random bytes as
 * RFC 5280 and the baseline requirements ask for.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class CertificateBuilder internal constructor() {
    internal val extensionsBuilder: ExtensionsBuilder = ExtensionsBuilder()

    internal val extensions: List<Extension> get() = extensionsBuilder.extensions.toList()

    /**
     * The serial number, or null for a random one.
     *
     * @since 1.0.0
     */
    public var serialNumber: DerInteger? = null

    /**
     * The name of the subject; empty by default, for a certificate that names its subject in alternative names.
     *
     * @since 1.0.0
     */
    public var subject: DistinguishedName = DistinguishedName.Empty

    /**
     * The name of the issuer, or null for a self-issued certificate.
     *
     * @since 1.0.0
     */
    public var issuer: DistinguishedName? = null

    /**
     * The public key of the subject; required.
     *
     * @since 1.0.0
     */
    public var publicKey: PublicKey? = null

    /**
     * The start of the validity; required.
     *
     * @since 1.0.0
     */
    public var notBefore: Instant? = null

    /**
     * The end of the validity, inclusive; required.
     *
     * @since 1.0.0
     */
    public var notAfter: Instant? = null

    /**
     * Sets the name of the subject.
     *
     * @param block adds the relative names.
     * @since 1.0.0
     */
    public fun subject(block: DistinguishedNameBuilder.() -> Unit) {
        subject = distinguishedName(block)
    }

    /**
     * Adds extensions.
     *
     * @param block adds the extensions.
     * @since 1.0.0
     */
    public fun extensions(block: ExtensionsBuilder.() -> Unit) {
        extensionsBuilder.block()
    }
}
