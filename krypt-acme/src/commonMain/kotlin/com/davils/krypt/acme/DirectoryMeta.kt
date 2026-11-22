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
 * The `meta` object of an ACME directory, by RFC 8555 section 7.1.1; every member is optional.
 *
 * Values are immutable and safe to share between threads.
 *
 * @property termsOfService the URL of the current terms of service, or null.
 * @property website the URL of the website of the server, or null.
 * @property caaIdentities the domain names the server recognizes in CAA records.
 * @property isExternalAccountRequired whether a new account needs an external account binding.
 * @since 1.0.0
 */
public class DirectoryMeta internal constructor(
    public val termsOfService: String?,
    public val website: String?,
    public val caaIdentities: List<String>,
    public val isExternalAccountRequired: Boolean,
) {
    private val values: List<Any?> get() = listOf(termsOfService, website, caaIdentities, isExternalAccountRequired)

    /**
     * Compares every member.
     *
     * @param other the other object.
     * @return true if [other] is the same meta object.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is DirectoryMeta && values == other.values

    /**
     * Hashes every member.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows whether an external account binding is required.
     *
     * @return the meta object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "DirectoryMeta(isExternalAccountRequired=$isExternalAccountRequired)"
}
