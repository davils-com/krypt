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

package com.davils.krypt.spiffe

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.spiffe.internal.CheckedId
import com.davils.krypt.spiffe.internal.IdParser
import com.davils.krypt.x509.name.GeneralName

/**
 * A SPIFFE id of the SPIFFE ID specification: `spiffe://`, a [TrustDomain] and an optional path, such as
 * `spiffe://example.org/ns/prod/sa/api`.
 *
 * [parse] is a hand-written parser without regular expressions that accepts exactly the canonical form: the scheme
 * `spiffe` and the trust domain in lower case, no user information, port, query, fragment or percent-encoding, path
 * segments of letters, digits, `.`, `-` and `_` that are neither empty nor `.` or `..`, no trailing `/`, and at most
 * [MAXIMUM_LENGTH] characters in all. The path compares with regard to case.
 *
 * Ids are immutable, compared by their text and safe to share between threads. Their text holds only the characters
 * above, so it is shown as it is.
 *
 * @property trustDomain the trust domain.
 * @property path the path, empty or starting with `/`, such as `/ns/prod/sa/api`.
 * @since 1.0.0
 */
public class SpiffeId private constructor(public val trustDomain: TrustDomain, public val path: String) :
    Comparable<SpiffeId> {
    /**
     * The id as text, such as `spiffe://example.org/ns/prod/sa/api`.
     *
     * @since 1.0.0
     */
    public val text: String = IdParser.PREFIX + trustDomain.name + path

    /**
     * The segments of the [path], empty for the id of a trust domain.
     *
     * @since 1.0.0
     */
    public val segments: List<String>
        get() = path.split(IdParser.SLASH).drop(1)

    /**
     * Whether the id has no path, as the id of a trust domain and of its signing authorities.
     *
     * @since 1.0.0
     */
    public val isTrustDomainId: Boolean get() = path.isEmpty()

    internal constructor(checked: CheckedId) : this(trustDomain = checked.trustDomain, path = checked.path)

    /**
     * Returns whether this id resides in [trustDomain].
     *
     * @param trustDomain the trust domain.
     * @return true if the trust domain of this id is [trustDomain].
     * @since 1.0.0
     */
    public fun memberOf(trustDomain: TrustDomain): Boolean = this.trustDomain == trustDomain

    /**
     * Returns the id as the URI subject alternative name of an X.509-SVID.
     *
     * @return the name.
     * @since 1.0.0
     */
    public fun toGeneralName(): GeneralName.Uri = GeneralName.Uri(text)

    /**
     * Orders ids by their text.
     *
     * @param other the other id.
     * @return the order of the texts.
     * @since 1.0.0
     */
    override fun compareTo(other: SpiffeId): Int = text.compareTo(other.text)

    /**
     * Compares the texts.
     *
     * @param other the other object.
     * @return true if [other] is the same id.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is SpiffeId && text == other.text

    /**
     * Hashes the text.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = text.hashCode()

    /**
     * Shows the id.
     *
     * @return the [text].
     * @since 1.0.0
     */
    override fun toString(): String = text

    /**
     * Parsing and building SPIFFE ids.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The longest id, which section 2.3 of the SPIFFE ID specification requires implementations to support.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_LENGTH: Int = 2_048

        /**
         * Parses a SPIFFE id.
         *
         * @param text the id, possibly from an attacker.
         * @return the id, or why the text is none.
         * @since 1.0.0
         */
        public fun parse(text: String): Outcome<SpiffeId, SpiffeIdFailure> = IdParser.parse(text)

        /**
         * Reads the SPIFFE id of a subject alternative name.
         *
         * @param name the name, possibly from an attacker.
         * @return the id, or why the name is none, [SpiffeIdFailure.WrongScheme] for a name that is no URI.
         * @since 1.0.0
         */
        public fun of(name: GeneralName): Outcome<SpiffeId, SpiffeIdFailure> {
            if (name !is GeneralName.Uri) return Outcome.Failure(SpiffeIdFailure.WrongScheme)
            return parse(name.uri)
        }

        /**
         * Builds the id of [trustDomain] with the path of [segments].
         *
         * @param trustDomain the trust domain.
         * @param segments the path segments, none for the id of the trust domain.
         * @return the id.
         * @throws IllegalArgumentException if a segment is empty, `.` or `..`, holds a character other than letters,
         *   digits, `.`, `-` and `_`, or the id is longer than [MAXIMUM_LENGTH].
         * @since 1.0.0
         */
        public fun of(trustDomain: TrustDomain, segments: List<String>): SpiffeId {
            val failure = segments.firstNotNullOfOrNull { segment ->
                IdParser.segmentFailure(segment = segment, isLast = false)
            }
            require(failure == null) { "A segment is invalid: ${failure?.name.orEmpty()}" }
            val path = segments.joinToString(separator = "") { segment -> IdParser.SLASH + segment }
            val id = SpiffeId(CheckedId(trustDomain = trustDomain, path = path))
            require(id.text.length <= MAXIMUM_LENGTH) { "A SPIFFE id has at most $MAXIMUM_LENGTH characters" }
            return id
        }
    }
}
