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

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.Certificate

/**
 * The result of a path validation.
 *
 * @since 1.0.0
 */
public sealed interface PathValidation {
    /**
     * Whether the path is valid.
     *
     * @since 1.0.0
     */
    public val isValid: Boolean

    /**
     * A valid path.
     *
     * @property path the certificates, the end entity first, the anchor not included.
     * @property anchor the trust anchor.
     * @property policies the certificate policies the path is valid for, or an empty set if it is valid for none.
     * @since 1.0.0
     */
    public class Valid internal constructor(
        public val path: List<Certificate>,
        public val anchor: TrustAnchor,
        public val policies: Set<ObjectIdentifier>,
    ) : PathValidation {
        override val isValid: Boolean get() = true

        /**
         * Shows the path.
         *
         * @return the result as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Valid(${path.size} certificates to $anchor)"
    }

    /**
     * An invalid path.
     *
     * @property failure why, for the path that came closest to an anchor.
     * @property certificate the certificate that failed, or the end entity if no path was found.
     * @since 1.0.0
     */
    public class Invalid internal constructor(
        public val failure: PathFailure,
        public val certificate: Certificate,
    ) : PathValidation {
        override val isValid: Boolean get() = false

        /**
         * Shows the failure.
         *
         * @return the result as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Invalid($failure, ${certificate.subject})"
    }
}
