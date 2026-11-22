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

/**
 * Why a text is no SPIFFE id or no trust domain name of the SPIFFE ID specification.
 *
 * @since 1.0.0
 */
public enum class SpiffeIdFailure {
    /**
     * The text is empty.
     *
     * @since 1.0.0
     */
    Empty,

    /**
     * The id is longer than [SpiffeId.MAXIMUM_LENGTH].
     *
     * @since 1.0.0
     */
    TooLong,

    /**
     * The text does not start with `spiffe://` in lower case.
     *
     * @since 1.0.0
     */
    WrongScheme,

    /**
     * The trust domain name is empty.
     *
     * @since 1.0.0
     */
    MissingTrustDomain,

    /**
     * The trust domain name is longer than [TrustDomain.MAXIMUM_LENGTH].
     *
     * @since 1.0.0
     */
    TrustDomainTooLong,

    /**
     * The trust domain name holds a character other than `a` to `z`, `0` to `9`, `.`, `-` and `_`, such as an upper
     * case letter.
     *
     * @since 1.0.0
     */
    BadTrustDomainCharacter,

    /**
     * The authority carries user information before an `@`.
     *
     * @since 1.0.0
     */
    UserInfo,

    /**
     * The authority carries a port after a `:`.
     *
     * @since 1.0.0
     */
    Port,

    /**
     * The id holds a percent-encoded character.
     *
     * @since 1.0.0
     */
    PercentEncoded,

    /**
     * The id has a query.
     *
     * @since 1.0.0
     */
    Query,

    /**
     * The id has a fragment.
     *
     * @since 1.0.0
     */
    Fragment,

    /**
     * A path segment holds a character other than letters, digits, `.`, `-` and `_`.
     *
     * @since 1.0.0
     */
    BadPathCharacter,

    /**
     * The path has an empty segment, such as in `a//b`.
     *
     * @since 1.0.0
     */
    EmptySegment,

    /**
     * The path has a segment `.` or `..`.
     *
     * @since 1.0.0
     */
    DotSegment,

    /**
     * The path ends with a `/`.
     *
     * @since 1.0.0
     */
    TrailingSlash,
}
