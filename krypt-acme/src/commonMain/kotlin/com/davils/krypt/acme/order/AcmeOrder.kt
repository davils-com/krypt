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

package com.davils.krypt.acme.order

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.acme.AcmeIdentifier
import com.davils.krypt.acme.AcmeProblem
import com.davils.krypt.acme.AcmeStatus
import com.davils.krypt.acme.internal.OrderTimes
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * An order of a certificate, by RFC 8555 section 7.1.3, with the `replaces` member of RFC 9773.
 *
 * Values are immutable and safe to share between threads.
 *
 * @property url the URL of the order.
 * @property status [AcmeStatus.Pending], [AcmeStatus.Ready], [AcmeStatus.Processing], [AcmeStatus.Valid] or
 *   [AcmeStatus.Invalid].
 * @property identifiers the identifiers the certificate is for.
 * @property authorizations the URLs of the authorizations to complete.
 * @property finalize the URL to send the certification request to.
 * @property certificate the URL of the certificate once the order is valid, or null.
 * @property error why the order became invalid, or null.
 * @property replaces the certificate identifier of RFC 9773 this order replaces, or null.
 * @property retryAfter how long the `Retry-After` field of the response asks to wait before polling again, or null.
 * @since 1.0.0
 */
public class AcmeOrder internal constructor(
    public val url: String,
    public val status: AcmeStatus,
    public val identifiers: List<AcmeIdentifier>,
    public val authorizations: List<String>,
    public val finalize: String,
    public val certificate: String?,
    private val times: OrderTimes,
    public val error: AcmeProblem?,
    public val replaces: String?,
    public val retryAfter: Duration?,
) {
    /**
     * When the server gives up on the order, or null.
     *
     * @since 1.0.0
     */
    public val expires: Instant? get() = times.expires

    /**
     * The requested start of the validity, or null.
     *
     * @since 1.0.0
     */
    public val notBefore: Instant? get() = times.notBefore

    /**
     * The requested end of the validity, or null.
     *
     * @since 1.0.0
     */
    public val notAfter: Instant? get() = times.notAfter

    private val values: List<Any?>
        get() = listOf(
            url,
            status,
            identifiers,
            authorizations,
            finalize,
            certificate,
            times,
            error,
            replaces,
            retryAfter,
        )

    /**
     * Compares every member.
     *
     * @param other the other object.
     * @return true if [other] is the same order.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeOrder && values == other.values

    /**
     * Hashes every member.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the URL, the status and the identifiers, escaped.
     *
     * @return the order as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeOrder(${SafeText.text(url)}, ${status.statusName}, $identifiers)"
}
