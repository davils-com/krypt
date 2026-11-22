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

import com.davils.krypt.jose.JoseLimits
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

/**
 * The limits of the ACME client on what a server sends and on how much the client retries.
 *
 * @property maximumResponseBytes the size of the body of one response.
 * @property maximumHeaders how many header fields one response carries.
 * @property maximumHeaderBytes the size of the name and the value of one header field.
 * @property maximumUrlLength the length of every URL the server names.
 * @property maximumEntries how many entries a list of the server holds: identifiers, authorizations, challenges,
 *   contacts, CAA identities and subproblems, and how many `Link` relations one response carries.
 * @property maximumCertificates how many certificates one downloaded chain holds.
 * @property maximumNonces how many unused nonces the client keeps; the oldest goes first.
 * @property maximumNonceRetries how often the client repeats a request the server refused with `badNonce`; 0 never.
 * @property maximumRetryAfter the longest wait a `Retry-After` field may ask for.
 * @property json the limits of the JSON of every response.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive, [maximumNonceRetries] is negative, or a limit exceeds
 *   its hard ceiling.
 * @since 1.0.0
 */
public class AcmeLimits(
    public val maximumResponseBytes: Int = DEFAULT_MAXIMUM_RESPONSE_BYTES,
    public val maximumHeaders: Int = DEFAULT_MAXIMUM_HEADERS,
    public val maximumHeaderBytes: Int = DEFAULT_MAXIMUM_HEADER_BYTES,
    public val maximumUrlLength: Int = DEFAULT_MAXIMUM_URL_LENGTH,
    public val maximumEntries: Int = DEFAULT_MAXIMUM_ENTRIES,
    public val maximumCertificates: Int = DEFAULT_MAXIMUM_CERTIFICATES,
    public val maximumNonces: Int = DEFAULT_MAXIMUM_NONCES,
    public val maximumNonceRetries: Int = DEFAULT_MAXIMUM_NONCE_RETRIES,
    public val maximumRetryAfter: Duration = DEFAULT_MAXIMUM_RETRY_AFTER,
    public val json: JoseLimits = JoseLimits.Default,
) {
    private val values: List<Any>
        get() = listOf(
            maximumResponseBytes,
            maximumHeaders,
            maximumHeaderBytes,
            maximumUrlLength,
            maximumEntries,
            maximumCertificates,
            maximumNonces,
            maximumNonceRetries,
            maximumRetryAfter,
            json,
        )

    init {
        require(maximumResponseBytes in 1..HARD_MAXIMUM_RESPONSE_BYTES) {
            "A response has 1 to $HARD_MAXIMUM_RESPONSE_BYTES bytes"
        }
        require(maximumHeaders in 1..HARD_MAXIMUM_HEADERS) { "A response has 1 to $HARD_MAXIMUM_HEADERS headers" }
        require(maximumHeaderBytes in 1..HARD_MAXIMUM_HEADER_BYTES) {
            "A header field has 1 to $HARD_MAXIMUM_HEADER_BYTES bytes"
        }
        require(maximumUrlLength in 1..HARD_MAXIMUM_URL_LENGTH) { "A URL has 1 to $HARD_MAXIMUM_URL_LENGTH characters" }
        require(maximumEntries in 1..HARD_MAXIMUM_ENTRIES) { "A list has 1 to $HARD_MAXIMUM_ENTRIES entries" }
        require(maximumCertificates in 1..HARD_MAXIMUM_CERTIFICATES) {
            "A chain has 1 to $HARD_MAXIMUM_CERTIFICATES certificates"
        }
        require(maximumNonces in 1..HARD_MAXIMUM_NONCES) { "The client keeps 1 to $HARD_MAXIMUM_NONCES nonces" }
        require(maximumNonceRetries in 0..HARD_MAXIMUM_NONCE_RETRIES) {
            "The client retries 0 to $HARD_MAXIMUM_NONCE_RETRIES times"
        }
        require(maximumRetryAfter.isPositive() && maximumRetryAfter <= HARD_MAXIMUM_RETRY_AFTER) {
            "A Retry-After asks for at most $HARD_MAXIMUM_RETRY_AFTER"
        }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeLimits && values == other.values

    /**
     * Hashes every limit.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows every limit.
     *
     * @return the limits as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeLimits(maximumResponseBytes=$maximumResponseBytes, " +
        "maximumHeaders=$maximumHeaders, maximumHeaderBytes=$maximumHeaderBytes, " +
        "maximumUrlLength=$maximumUrlLength, maximumEntries=$maximumEntries, " +
        "maximumCertificates=$maximumCertificates, maximumNonces=$maximumNonces, " +
        "maximumNonceRetries=$maximumNonceRetries, maximumRetryAfter=$maximumRetryAfter, json=$json)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a response body.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_RESPONSE_BYTES: Int = 262_144

        /**
         * The hard ceiling of the size of a response body.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_RESPONSE_BYTES: Int = 16_777_216

        /**
         * The default number of header fields.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_HEADERS: Int = 64

        /**
         * The hard ceiling of the number of header fields.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_HEADERS: Int = 1_024

        /**
         * The default size of a header field.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_HEADER_BYTES: Int = 8_192

        /**
         * The hard ceiling of the size of a header field.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_HEADER_BYTES: Int = 65_536

        /**
         * The default length of a URL.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_URL_LENGTH: Int = 2_048

        /**
         * The hard ceiling of the length of a URL.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_URL_LENGTH: Int = 8_192

        /**
         * The default number of entries of a list.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_ENTRIES: Int = 100

        /**
         * The hard ceiling of the number of entries of a list.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ENTRIES: Int = 1_000

        /**
         * The default number of certificates of a chain.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_CERTIFICATES: Int = 8

        /**
         * The hard ceiling of the number of certificates of a chain.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_CERTIFICATES: Int = 64

        /**
         * The default number of nonces kept.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_NONCES: Int = 16

        /**
         * The hard ceiling of the number of nonces kept.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_NONCES: Int = 256

        /**
         * The default number of retries after `badNonce`.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_NONCE_RETRIES: Int = 3

        /**
         * The hard ceiling of the number of retries after `badNonce`.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_NONCE_RETRIES: Int = 16

        /**
         * The default longest wait of a `Retry-After` field, one day.
         *
         * @since 1.0.0
         */
        public val DEFAULT_MAXIMUM_RETRY_AFTER: Duration = 1.days

        /**
         * The hard ceiling of the wait of a `Retry-After` field, seven days.
         *
         * @since 1.0.0
         */
        public val HARD_MAXIMUM_RETRY_AFTER: Duration = 7.days

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: AcmeLimits = AcmeLimits()
    }
}
