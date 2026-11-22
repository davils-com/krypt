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

package com.davils.krypt.ocsp

import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.path.TrustAnchor

/**
 * The issuer of the certificates an OCSP message is about: its name and its public key.
 *
 * @property name the name of the issuer.
 * @property publicKey the public key of the issuer.
 * @constructor Describes an issuer.
 * @since 1.0.0
 */
public class OcspIssuer(public val name: DistinguishedName, public val publicKey: PublicKey) {
    /**
     * Compares the name and the key.
     *
     * @param other the other object.
     * @return true if [other] is the same issuer.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is OcspIssuer && name == other.name && publicKey == other.publicKey

    /**
     * Hashes the name.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = name.hashCode()

    /**
     * Shows the name.
     *
     * @return the issuer as text.
     * @since 1.0.0
     */
    override fun toString(): String = "OcspIssuer($name)"

    /**
     * Creating issuers.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the issuer that [certificate] describes: its subject and its key.
         *
         * @param certificate the certificate of the issuer.
         * @return the issuer.
         * @throws IllegalArgumentException if krypt cannot read the key of [certificate] or the policy forbids it.
         * @since 1.0.0
         */
        public fun of(certificate: Certificate): OcspIssuer {
            val key = requireNotNull(certificate.publicKey) { "The key of the issuer is not usable" }
            return OcspIssuer(certificate.subject, key)
        }

        /**
         * Returns the issuer that [anchor] describes.
         *
         * @param anchor the trust anchor.
         * @return the issuer.
         * @since 1.0.0
         */
        public fun of(anchor: TrustAnchor): OcspIssuer = OcspIssuer(anchor.name, anchor.publicKey)
    }
}
