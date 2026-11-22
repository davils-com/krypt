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

package com.davils.krypt.keystore.pkcs12

/**
 * The content of a PKCS #12 file: keys with their chains and certificates of their own.
 *
 * @constructor Creates the content.
 * @since 1.0.0
 */
public class Pkcs12Store(keys: List<KeyEntry> = emptyList(), certificates: List<CertificateEntry> = emptyList()) {
    /**
     * The keys with their chains.
     *
     * @since 1.0.0
     */
    public val keys: List<KeyEntry> = keys.toList()

    /**
     * The certificates of their own, such as trust anchors.
     *
     * @since 1.0.0
     */
    public val certificates: List<CertificateEntry> = certificates.toList()

    /**
     * Finds the key with [alias].
     *
     * @param alias the friendly name.
     * @return the entry, or null.
     * @since 1.0.0
     */
    public fun key(alias: String): KeyEntry? = keys.firstOrNull { entry -> entry.alias == alias }

    /**
     * Compares the entries.
     *
     * @param other the other object.
     * @return true if [other] holds the same entries.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is Pkcs12Store && keys == other.keys && certificates == other.certificates

    /**
     * Hashes the entries.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(keys, certificates).hashCode()

    /**
     * Shows the entries.
     *
     * @return the store as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Pkcs12Store(keys=$keys, certificates=$certificates)"
}
