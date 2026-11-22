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

package com.davils.krypt.spiffe.jwt

/**
 * Why a token is no valid JWT-SVID of the JWT-SVID specification.
 *
 * @since 1.0.0
 */
public enum class JwtSvidFailure {
    /**
     * The token is no compact JWS with a JSON object of claims, such as a JWE, the JSON serialization or invalid
     * Base64url.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The token is longer than the limit.
     *
     * @since 1.0.0
     */
    LimitExceeded,

    /**
     * The `alg` of the header is none of the algorithms of the validator.
     *
     * @since 1.0.0
     */
    UnsupportedAlgorithm,

    /**
     * The header has a member other than `alg`, `kid` and `typ`, which section 2 of the specification forbids.
     *
     * @since 1.0.0
     */
    UnsupportedHeader,

    /**
     * The header has no `kid`.
     *
     * @since 1.0.0
     */
    MissingKeyId,

    /**
     * The `typ` of the header is neither `JWT` nor `JOSE`.
     *
     * @since 1.0.0
     */
    WrongType,

    /**
     * The `sub` claim is missing or no SPIFFE id.
     *
     * @since 1.0.0
     */
    InvalidSubject,

    /**
     * No bundle is known for the trust domain of the subject.
     *
     * @since 1.0.0
     */
    NoBundle,

    /**
     * The bundle of the trust domain of the subject has no JWT authority with the `kid` of the token, or its key does
     * not fit the algorithm.
     *
     * @since 1.0.0
     */
    KeyNotFound,

    /**
     * The signature is wrong.
     *
     * @since 1.0.0
     */
    BadSignature,

    /**
     * The `aud` claim is missing or does not name the audience of the validator.
     *
     * @since 1.0.0
     */
    WrongAudience,

    /**
     * The `exp` claim is missing.
     *
     * @since 1.0.0
     */
    MissingExpiration,

    /**
     * The token expired, beyond the allowed clock skew.
     *
     * @since 1.0.0
     */
    Expired,

    /**
     * The token is not valid yet by `nbf` or `iat`, beyond the allowed clock skew.
     *
     * @since 1.0.0
     */
    NotYetValid,
}
