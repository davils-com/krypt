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

package com.davils.krypt.keystore.material

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.core.SecretText

/**
 * Where an identity lies and how it is protected.
 *
 * A spec holds the password it was given and does not destroy it; the caller destroys it when no longer needed.
 *
 * @since 1.0.0
 */
public sealed interface IdentitySpec {
    /**
     * A PKCS #12 file.
     *
     * @property ref the file.
     * @property password the password of the file.
     * @property alias the friendly name of the key, or null for the only key of the file.
     * @constructor Creates the spec.
     * @since 1.0.0
     */
    public class KeyStore(
        public val ref: MaterialRef,
        public val password: SecretText,
        public val alias: String? = null,
    ) : IdentitySpec {
        /**
         * Shows the reference and the alias, never the password.
         *
         * @return the spec as text.
         * @since 1.0.0
         */
        @OptIn(DavilsInternal::class)
        override fun toString(): String {
            val shown = SafeText.text(alias ?: "none")
            return "KeyStore($ref, alias=$shown)"
        }
    }

    /**
     * PEM text: a certificate chain and a private key, in two references or together in one.
     *
     * The chain is the CERTIFICATE blocks of [certificates]; the key is the only private key block of [key], in
     * PKCS #8, encrypted PKCS #8, SEC 1 or PKCS #1.
     *
     * @property certificates the chain.
     * @property key the private key; it may be the same reference as [certificates].
     * @property password the password of an encrypted key, or null.
     * @constructor Creates the spec.
     * @since 1.0.0
     */
    public class PemBundle(
        public val certificates: MaterialRef,
        public val key: MaterialRef = certificates,
        public val password: SecretText? = null,
    ) : IdentitySpec {
        /**
         * Shows the references, never the password.
         *
         * @return the spec as text.
         * @since 1.0.0
         */
        override fun toString(): String = "PemBundle($certificates, $key, encrypted=${password != null})"
    }
}
