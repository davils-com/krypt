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

package com.davils.krypt.spiffe

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.text.SafeText
import com.davils.krypt.spiffe.internal.CheckedDomain
import com.davils.krypt.spiffe.internal.CheckedId
import com.davils.krypt.spiffe.internal.IdParser

/**
 * A SPIFFE trust domain: the authority of a SPIFFE id and the namespace its authorities are trusted for.
 *
 * A name is 1 to [MAXIMUM_LENGTH] characters of `a` to `z`, `0` to `9`, `.`, `-` and `_`, as section 2.1 of the
 * SPIFFE ID specification demands; IP addresses in dotted-quad form are names like any other, and nothing is
 * resolved. Upper case is refused rather than folded, so that one trust domain has exactly one spelling.
 *
 * Trust domains are compared by their name, immutable and safe to share between threads.
 *
 * @property name the name, such as `example.org`.
 * @since 1.0.0
 */
public class TrustDomain private constructor(public val name: String) : Comparable<TrustDomain> {
    /**
     * The SPIFFE id of the trust domain itself, `spiffe://` and the [name] without a path, which signing authorities
     * carry.
     *
     * @since 1.0.0
     */
    public val id: SpiffeId get() = SpiffeId(CheckedId(trustDomain = this, path = ""))

    internal constructor(checked: CheckedDomain) : this(checked.name)

    /**
     * Returns the SPIFFE id of this trust domain with the path of [segments].
     *
     * @param segments the path segments, such as `ns`, `prod`, `sa` and `api`.
     * @return the id.
     * @throws IllegalArgumentException if a segment is empty, `.` or `..`, holds a character other than letters,
     *   digits, `.`, `-` and `_`, or the id is longer than [SpiffeId.MAXIMUM_LENGTH].
     * @since 1.0.0
     */
    public fun idOf(vararg segments: String): SpiffeId = SpiffeId.of(trustDomain = this, segments = segments.toList())

    /**
     * Orders trust domains by their name.
     *
     * @param other the other trust domain.
     * @return the order of the names.
     * @since 1.0.0
     */
    override fun compareTo(other: TrustDomain): Int = name.compareTo(other.name)

    /**
     * Compares the names.
     *
     * @param other the other object.
     * @return true if [other] is the same trust domain.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TrustDomain && name == other.name

    /**
     * Hashes the name.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = name.hashCode()

    /**
     * Shows the name.
     *
     * @return the name.
     * @since 1.0.0
     */
    override fun toString(): String = name

    /**
     * Parsing trust domain names.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The longest name, the limit of a host of RFC 3986.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_LENGTH: Int = 255

        /**
         * Parses the name of a trust domain, without the `spiffe://` scheme.
         *
         * @param name the name, possibly from an attacker.
         * @return the trust domain, or why the name is none.
         * @since 1.0.0
         */
        public fun parse(name: String): Outcome<TrustDomain, SpiffeIdFailure> {
            val failure = IdParser.trustDomainFailure(name)
                ?: return Outcome.Success(TrustDomain(CheckedDomain(name)))
            return Outcome.Failure(failure)
        }

        /**
         * Returns the trust domain [name].
         *
         * @param name the name, such as `example.org`.
         * @return the trust domain.
         * @throws IllegalArgumentException if [name] is no trust domain name.
         * @since 1.0.0
         */
        public fun of(name: String): TrustDomain {
            val failure = IdParser.trustDomainFailure(name)
            require(failure == null) { "${SafeText.quoted(name)} is no trust domain name: ${failure?.name.orEmpty()}" }
            return TrustDomain(CheckedDomain(name))
        }
    }
}
