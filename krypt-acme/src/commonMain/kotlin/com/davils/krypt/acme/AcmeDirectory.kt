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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.acme

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText

/**
 * The directory of an ACME server, by RFC 8555 section 7.1.1, with the `renewalInfo` resource of RFC 9773.
 *
 * Every URL is checked: absolute `https`, or `http` where the transport allows it. Values are immutable and safe to
 * share between threads.
 *
 * @property newNonce the URL for fresh nonces.
 * @property newAccount the URL for new accounts and for finding an account by its key.
 * @property newOrder the URL for new orders.
 * @property newAuthorization the URL for pre-authorization, or null if the server offers none.
 * @property revokeCertificate the URL for revocation, or null if the server offers none.
 * @property keyChange the URL for key rollover, or null if the server offers none.
 * @property renewalInfo the URL of the renewal information of RFC 9773, or null if the server offers none.
 * @property meta the `meta` object.
 * @since 1.0.0
 */
public class AcmeDirectory internal constructor(
    public val newNonce: String,
    public val newAccount: String,
    public val newOrder: String,
    public val newAuthorization: String?,
    public val revokeCertificate: String?,
    public val keyChange: String?,
    public val renewalInfo: String?,
    public val meta: DirectoryMeta,
) {
    private val values: List<Any?>
        get() = listOf(
            newNonce,
            newAccount,
            newOrder,
            newAuthorization,
            revokeCertificate,
            keyChange,
            renewalInfo,
            meta,
        )

    /**
     * Compares every resource and the meta object.
     *
     * @param other the other object.
     * @return true if [other] is the same directory.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeDirectory && values == other.values

    /**
     * Hashes every resource and the meta object.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows where new accounts are made, escaped.
     *
     * @return the directory as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeDirectory(${SafeText.text(newAccount)})"
}
