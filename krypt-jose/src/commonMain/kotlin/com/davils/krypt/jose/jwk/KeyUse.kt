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

package com.davils.krypt.jose.jwk

/**
 * The intended use of a public key, the `use` member of a JWK.
 *
 * @property useName the name in a JWK.
 * @since 1.0.0
 */
public enum class KeyUse(public val useName: String) {
    /**
     * Signatures.
     *
     * @since 1.0.0
     */
    Signature("sig"),

    /**
     * Encryption.
     *
     * @since 1.0.0
     */
    Encryption("enc"),
    ;

    /**
     * The lookup by name.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the use named [name].
         *
         * @param name the name in a JWK.
         * @return the use, or null if krypt does not know it.
         * @since 1.0.0
         */
        public fun of(name: String): KeyUse? = entries.firstOrNull { use -> use.useName == name }
    }
}
