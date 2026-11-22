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

package com.davils.krypt.cms.enveloped

import com.davils.krypt.core.SecretText
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.SecretKey
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

/**
 * What a recipient opens enveloped data with.
 *
 * @since 1.0.0
 */
public sealed interface Credential {
    /**
     * A private key and its certificate, for key transport, key agreement and KEM recipients that name the
     * certificate.
     *
     * @property certificate the recipient's certificate.
     * @property privateKey its private key, possibly in an HSM.
     * @constructor Holds the credential.
     * @since 1.0.0
     */
    public class Certified(public val certificate: Certificate, public val privateKey: PrivateKey) : Credential {
        /**
         * Compares the certificate and the key handle.
         *
         * @param other the other object.
         * @return true if [other] holds the same certificate and key.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean =
            other is Certified && listOf(certificate, privateKey) == listOf(other.certificate, other.privateKey)

        /**
         * Hashes the certificate.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = certificate.hashCode()

        /**
         * Shows the subject, never the key.
         *
         * @return the credential as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Certified(${certificate.subject})"
    }

    /**
     * A shared key-encryption key, for KEK recipients with this identifier.
     *
     * @property keyIdentifier the identifier of the key.
     * @property key the key.
     * @constructor Holds the credential.
     * @since 1.0.0
     */
    public class Kek(public val keyIdentifier: ByteString, public val key: SecretKey) : Credential {
        /**
         * Compares the identifier and the key, the key in constant time.
         *
         * @param other the other object.
         * @return true if [other] holds the same key.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean =
            other is Kek && listOf(keyIdentifier, key) == listOf(other.keyIdentifier, other.key)

        /**
         * Hashes the identifier only.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = keyIdentifier.hashCode()

        /**
         * Shows the identifier, never the key.
         *
         * @return the credential as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Kek(${Hex.encode(keyIdentifier)})"
    }

    /**
     * A password, for password recipients.
     *
     * @property password the password.
     * @constructor Holds the credential.
     * @since 1.0.0
     */
    public class Password(public val password: SecretText) : Credential {
        /**
         * Compares the passwords in constant time.
         *
         * @param other the other object.
         * @return true if [other] holds the same password.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean = other is Password && password == other.password

        /**
         * Hashes the length only.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = password.length

        /**
         * Shows nothing of the password.
         *
         * @return the credential as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Password(redacted)"
    }
}
