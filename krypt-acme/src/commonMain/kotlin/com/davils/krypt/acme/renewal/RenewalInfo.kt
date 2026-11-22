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

package com.davils.krypt.acme.renewal

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * The renewal information of a certificate, by RFC 9773 section 4.2: the window in which the server suggests to
 * renew it.
 *
 * The window is checked: it ends after it starts, or the response is malformed. Values are immutable and safe to
 * share between threads.
 *
 * @property certificateId the certificate identifier the information is about.
 * @property start the start of the suggested window.
 * @property end the end of the suggested window, after [start].
 * @property explanation the URL of a page that explains the window, or null.
 * @property retryAfter how long the `Retry-After` field of the response asks to wait before asking again, or null.
 * @since 1.0.0
 */
public class RenewalInfo internal constructor(
    public val certificateId: String,
    public val start: Instant,
    public val end: Instant,
    public val explanation: String?,
    public val retryAfter: Duration?,
) {
    private val values: List<Any?> get() = listOf(certificateId, start, end, explanation, retryAfter)

    /**
     * Tells whether [now] lies at or after the start of the window: the caller should renew.
     *
     * @param now the time to check.
     * @return true if the window has started.
     * @since 1.0.0
     */
    public fun isRenewalDue(now: Instant): Boolean = now >= start

    /**
     * Compares every member.
     *
     * @param other the other object.
     * @return true if [other] is the same information.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is RenewalInfo && values == other.values

    /**
     * Hashes every member.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the identifier and the window.
     *
     * @return the information as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RenewalInfo(${SafeText.text(certificateId)}, $start to $end)"
}
