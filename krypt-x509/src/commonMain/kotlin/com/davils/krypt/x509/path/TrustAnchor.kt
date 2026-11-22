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

package com.davils.krypt.x509.path

import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.extension.NameConstraints
import com.davils.krypt.x509.name.DistinguishedName

/**
 * A trust anchor: a name and a public key the application trusts, usually taken from a root certificate.
 *
 * Only the name, the key and the optional name constraints of an anchor count; the validity and the other extensions
 * of its certificate are not checked, as RFC 5280 prescribes.
 *
 * @property name the name of the anchor.
 * @property publicKey the public key.
 * @property nameConstraints constraints the anchor imposes on every path, or null.
 * @property certificate the certificate the anchor comes from, or null.
 * @constructor Trusts [publicKey] under [name].
 * @since 1.0.0
 */
public class TrustAnchor(
    public val name: DistinguishedName,
    public val publicKey: PublicKey,
    public val nameConstraints: NameConstraints? = null,
    public val certificate: Certificate? = null,
) {
    /**
     * Compares the name and the key.
     *
     * @param other the other object.
     * @return true if [other] is the same anchor.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is TrustAnchor && name == other.name && publicKey == other.publicKey

    /**
     * Hashes the name and the key.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(name, publicKey).hashCode()

    /**
     * Shows the name.
     *
     * @return the anchor as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TrustAnchor($name)"

    /**
     * Creating anchors.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the anchor of [certificate]: its subject, its key and its name constraints.
         *
         * @param certificate the root certificate.
         * @return the anchor.
         * @throws IllegalArgumentException if krypt cannot read the key of [certificate] or the policy forbids it.
         * @since 1.0.0
         */
        public fun of(certificate: Certificate): TrustAnchor = TrustAnchor(
            name = certificate.subject,
            publicKey = requireNotNull(certificate.publicKey) { "The key of the anchor is not usable" },
            nameConstraints = certificate.extensions.nameConstraints,
            certificate = certificate,
        )
    }
}
