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

package com.davils.krypt.acme

/**
 * The types of identifiers a certificate may be ordered for.
 *
 * @property typeName the name in JSON.
 * @since 1.0.0
 */
public enum class IdentifierType(public val typeName: String) {
    /**
     * A DNS name of RFC 8555, possibly a wildcard such as `*.example.org` in an order.
     *
     * @since 1.0.0
     */
    Dns("dns"),

    /**
     * An IPv4 or IPv6 address of RFC 8738, in its textual form.
     *
     * @since 1.0.0
     */
    Ip("ip"),
    ;

    /**
     * Finds identifier types by name.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the identifier type named [name].
         *
         * @param name the name in JSON.
         * @return the type, or null if [name] names none krypt supports.
         * @since 1.0.0
         */
        public fun of(name: String): IdentifierType? = entries.firstOrNull { type -> type.typeName == name }
    }
}
