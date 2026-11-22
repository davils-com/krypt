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

package com.davils.krypt.acme.order

/**
 * The challenge types krypt answers.
 *
 * @property typeName the name in JSON.
 * @since 1.0.0
 */
public enum class ChallengeType(public val typeName: String) {
    /**
     * A file under `/.well-known/acme-challenge/` over HTTP, by RFC 8555 section 8.3.
     *
     * @since 1.0.0
     */
    Http01("http-01"),

    /**
     * A TXT record at `_acme-challenge`, by RFC 8555 section 8.4.
     *
     * @since 1.0.0
     */
    Dns01("dns-01"),

    /**
     * A validation certificate over TLS with ALPN `acme-tls/1`, by RFC 8737.
     *
     * @since 1.0.0
     */
    TlsAlpn01("tls-alpn-01"),
    ;

    /**
     * Finds challenge types by name.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the challenge type named [name].
         *
         * @param name the name in JSON.
         * @return the type, or null if krypt does not know it.
         * @since 1.0.0
         */
        public fun of(name: String): ChallengeType? = entries.firstOrNull { type -> type.typeName == name }
    }
}
