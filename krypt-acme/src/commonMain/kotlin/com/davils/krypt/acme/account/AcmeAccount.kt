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

package com.davils.krypt.acme.account

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.acme.AcmeStatus

/**
 * An ACME account as the server describes it, by RFC 8555 section 7.1.2.
 *
 * Values are immutable and safe to share between threads.
 *
 * @property url the URL of the account, its key id for every later request.
 * @property status [AcmeStatus.Valid], [AcmeStatus.Deactivated] or [AcmeStatus.Revoked].
 * @property contacts the contact URLs, such as `mailto:` addresses.
 * @property isTermsOfServiceAgreed whether the holder agreed to the terms of service, or null if the server does not
 *   say.
 * @property orders the URL of the list of orders, or null if the server names none.
 * @property isCreated whether the request created the account rather than found an existing one.
 * @since 1.0.0
 */
public class AcmeAccount internal constructor(
    public val url: String,
    public val status: AcmeStatus,
    public val contacts: List<String>,
    public val isTermsOfServiceAgreed: Boolean?,
    public val orders: String?,
    public val isCreated: Boolean,
) {
    private val values: List<Any?> get() = listOf(url, status, contacts, isTermsOfServiceAgreed, orders, isCreated)

    /**
     * Compares every member.
     *
     * @param other the other object.
     * @return true if [other] is the same account.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeAccount && values == other.values

    /**
     * Hashes every member.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the URL and the status, never the contacts.
     *
     * @return the account as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeAccount(${SafeText.text(url)}, ${status.statusName})"
}
