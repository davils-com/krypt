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

import com.davils.krypt.x509.RevocationReason
import kotlin.time.Instant

/**
 * The status of a certificate in an OCSP response.
 *
 * @since 1.0.0
 */
public sealed interface CertificateStatus {
    /**
     * The certificate is not revoked.
     *
     * @since 1.0.0
     */
    public object Good : CertificateStatus {
        /**
         * Shows the status.
         *
         * @return the status as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Good"
    }

    /**
     * The responder does not know the certificate.
     *
     * @since 1.0.0
     */
    public object Unknown : CertificateStatus {
        /**
         * Shows the status.
         *
         * @return the status as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Unknown"
    }

    /**
     * The certificate is revoked.
     *
     * @property revokedAt when it was revoked.
     * @property reason why, or null.
     * @constructor Describes a revocation.
     * @since 1.0.0
     */
    public class Revoked(public val revokedAt: Instant, public val reason: RevocationReason? = null) :
        CertificateStatus {
        /**
         * Compares the time and the reason.
         *
         * @param other the other object.
         * @return true if [other] is the same revocation.
         * @since 1.0.0
         */
        override fun equals(other: Any?): Boolean =
            other is Revoked && revokedAt == other.revokedAt && reason == other.reason

        /**
         * Hashes the time.
         *
         * @return the hash.
         * @since 1.0.0
         */
        override fun hashCode(): Int = revokedAt.hashCode()

        /**
         * Shows the time and the reason.
         *
         * @return the status as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Revoked(at=$revokedAt, reason=${reason ?: NONE})"

        private companion object {
            const val NONE: String = "none"
        }
    }
}
