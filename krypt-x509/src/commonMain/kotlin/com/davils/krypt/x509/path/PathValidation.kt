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
import com.davils.krypt.x509.internal.PathRefusal
import com.davils.krypt.x509.internal.ValidPath

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
     * Only [PathValidator] creates one: its constructor takes a type of an internal package that the Java module does
     * not export, so the result cannot be forged.
     *
     * @since 1.0.0
     */
    public class Valid internal constructor(parts: ValidPath) : PathValidation {
        /**
         * The certificates, the end entity first, the anchor not included.
         *
         * @since 1.0.0
         */
        public val path: List<Certificate> = parts.path

        /**
         * The trust anchor.
         *
         * @since 1.0.0
         */
        public val anchor: TrustAnchor = parts.anchor

        /**
         * The certificate policies the path is valid for, or an empty set if it is valid for none.
         *
         * @since 1.0.0
         */
        public val policies: Set<ObjectIdentifier> = parts.policies

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
     * Only [PathValidator] creates one, like [Valid].
     *
     * @since 1.0.0
     */
    public class Invalid internal constructor(refusal: PathRefusal) : PathValidation {
        /**
         * Why, for the path that came closest to an anchor.
         *
         * @since 1.0.0
         */
        public val failure: PathFailure = refusal.failure

        /**
         * The certificate that failed, or the end entity if no path was found.
         *
         * @since 1.0.0
         */
        public val certificate: Certificate = refusal.certificate

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
