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
import com.davils.krypt.acme.AcmeStatus
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * An authorization of an identifier, by RFC 8555 section 7.1.4.
 *
 * Values are immutable and safe to share between threads.
 *
 * @property url the URL of the authorization.
 * @property identifier the identifier, without the `*.` of a wildcard.
 * @property status [AcmeStatus.Pending], [AcmeStatus.Valid], [AcmeStatus.Invalid], [AcmeStatus.Deactivated],
 *   [AcmeStatus.Expired] or [AcmeStatus.Revoked].
 * @property challenges the challenges the server offers.
 * @property expires when the authorization expires, or null.
 * @property isWildcard whether the authorization is for the wildcard of [identifier].
 * @property retryAfter how long the `Retry-After` field of the response asks to wait, or null.
 * @since 1.0.0
 */
public class AcmeAuthorization internal constructor(
    public val url: String,
    public val identifier: AcmeIdentifier,
    public val status: AcmeStatus,
    public val challenges: List<AcmeChallenge>,
    public val expires: Instant?,
    public val isWildcard: Boolean,
    public val retryAfter: Duration?,
) {
    private val values: List<Any?>
        get() = listOf(url, identifier, status, challenges, expires, isWildcard, retryAfter)

    /**
     * Returns the first challenge of [type].
     *
     * @param type the challenge type.
     * @return the challenge, or null if the server offers none of [type].
     * @since 1.0.0
     */
    public fun challenge(type: ChallengeType): AcmeChallenge? = challenges.firstOrNull { found -> found.kind == type }

    /**
     * Compares every member.
     *
     * @param other the other object.
     * @return true if [other] is the same authorization.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeAuthorization && values == other.values

    /**
     * Hashes every member.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the URL, the identifier and the status, escaped.
     *
     * @return the authorization as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeAuthorization(${SafeText.text(url)}, $identifier, ${status.statusName})"
}
