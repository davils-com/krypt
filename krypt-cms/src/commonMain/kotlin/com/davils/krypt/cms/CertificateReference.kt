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

package com.davils.krypt.cms

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

/**
 * How a signer or a recipient names its certificate: by issuer and serial number or by subject key identifier, the
 * SignerIdentifier and RecipientIdentifier of RFC 5652.
 *
 * @since 1.0.0
 */
public sealed interface CertificateReference {
    /**
     * Tells whether [certificate] is the one this reference names.
     *
     * @param certificate the candidate.
     * @return true if the issuer and serial number, or the subject key identifier, match.
     * @since 1.0.0
     */
    public fun matches(certificate: Certificate): Boolean

    /**
     * A certificate named by the DER encoding of its issuer and its serial number.
     *
     * @property issuer the DER encoding of the issuer's distinguished name, compared byte for byte.
     * @property serialNumber the serial number.
     * @constructor Names the certificate [serialNumber] of [issuer].
     * @since 1.0.0
     */
    public class IssuerSerial(public val issuer: ByteString, public val serialNumber: DerInteger) :
        CertificateReference {
        /**
         * Tells whether [certificate] has this issuer and serial number.
         *
         * @param certificate the candidate.
         * @return true if both match.
         * @since 1.0.0
         */
        override fun matches(certificate: Certificate): Boolean =
            certificate.serialNumber == serialNumber && certificate.issuer.encoded == issuer

        /**
         * Compares the issuer and the serial number.
         *
         * @param other the other object.
         * @return true if [other] names the same certificate.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean =
            other is IssuerSerial && listOf(issuer, serialNumber) == listOf(other.issuer, other.serialNumber)

        /**
         * Hashes the issuer and the serial number.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = listOf(issuer, serialNumber).hashCode()

        /**
         * Shows the serial number.
         *
         * @return the reference as text.
         * @since 1.0.0
         */
        override fun toString(): String = "IssuerSerial(${Hex.encode(serialNumber.bytes)})"

        /**
         * Builds references from certificates.
         *
         * @since 1.0.0
         */
        public companion object {
            /**
             * Names [certificate] by its issuer and serial number.
             *
             * @param certificate the certificate.
             * @return the reference.
             * @since 1.0.0
             */
            public fun of(certificate: Certificate): IssuerSerial =
                IssuerSerial(issuer = certificate.issuer.encoded, serialNumber = certificate.serialNumber)
        }
    }

    /**
     * A certificate named by the value of its subject key identifier extension.
     *
     * @property keyIdentifier the subject key identifier.
     * @constructor Names the certificate with [keyIdentifier].
     * @since 1.0.0
     */
    public class KeyIdentifier(public val keyIdentifier: ByteString) : CertificateReference {
        /**
         * Tells whether [certificate] carries this subject key identifier.
         *
         * @param certificate the candidate.
         * @return true if its subject key identifier extension has this value.
         * @since 1.0.0
         */
        override fun matches(certificate: Certificate): Boolean =
            certificate.extensions.subjectKeyIdentifier == keyIdentifier

        /**
         * Compares the key identifiers.
         *
         * @param other the other object.
         * @return true if [other] names the same key identifier.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is KeyIdentifier && keyIdentifier == other.keyIdentifier

        /**
         * Hashes the key identifier.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = keyIdentifier.hashCode()

        /**
         * Shows the key identifier in hex.
         *
         * @return the reference as text.
         * @since 1.0.0
         */
        override fun toString(): String = "KeyIdentifier(${Hex.encode(keyIdentifier)})"

        /**
         * Builds references from certificates.
         *
         * @since 1.0.0
         */
        public companion object {
            /**
             * Names [certificate] by its subject key identifier.
             *
             * @param certificate the certificate.
             * @return the reference.
             * @throws IllegalArgumentException if [certificate] has no subject key identifier extension.
             * @since 1.0.0
             */
            public fun of(certificate: Certificate): KeyIdentifier {
                val identifier = requireNotNull(certificate.extensions.subjectKeyIdentifier) {
                    "The certificate has no subject key identifier"
                }
                return KeyIdentifier(identifier)
            }
        }
    }
}
