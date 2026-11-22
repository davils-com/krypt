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
import com.davils.krypt.acme.AcmeProblem
import com.davils.krypt.acme.AcmeStatus
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * A challenge of an authorization, by RFC 8555 section 7.1.5.
 *
 * The token of a known type is checked: base64url without padding, at least 22 characters, so it carries 128 bits
 * and is safe in a path and a DNS name. Values are immutable and safe to share between threads.
 *
 * @property url the URL to respond to.
 * @property type the type as the server names it.
 * @property kind the type, or null if krypt does not know it.
 * @property status [AcmeStatus.Pending], [AcmeStatus.Processing], [AcmeStatus.Valid] or [AcmeStatus.Invalid].
 * @property token the token of a known type, or null for an unknown type.
 * @property validated when the server validated it, or null.
 * @property error why the validation failed, or null.
 * @property retryAfter how long the `Retry-After` field of the response asks to wait, or null.
 * @since 1.0.0
 */
public class AcmeChallenge internal constructor(
    public val url: String,
    public val type: String,
    public val kind: ChallengeType?,
    public val status: AcmeStatus,
    public val token: String?,
    public val validated: Instant?,
    public val error: AcmeProblem?,
    public val retryAfter: Duration?,
) {
    private val values: List<Any?> get() = listOf(url, type, status, token, validated, error, retryAfter)

    /**
     * Compares every member.
     *
     * @param other the other object.
     * @return true if [other] is the same challenge.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeChallenge && values == other.values

    /**
     * Hashes every member.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the type and the status, escaped.
     *
     * @return the challenge as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeChallenge(${SafeText.text(type)}, ${status.statusName})"
}
