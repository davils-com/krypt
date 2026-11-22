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

package com.davils.krypt.jose

/**
 * Why JOSE refused an input. Every decoder, verifier, decryptor and validator of krypt-jose reports bad input
 * through one of these values and never through an exception.
 *
 * @since 1.0.0
 */
public enum class JoseFailure {
    /**
     * The input is not valid: broken JSON, Base64url or serialization, a repeated member, a member of the wrong type,
     * a missing required member or key parameters that do not fit together.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The input breaks a limit of [JoseLimits].
     *
     * @since 1.0.0
     */
    LimitExceeded,

    /**
     * The input names an algorithm, a key type, a curve or a feature krypt does not implement, such as `none`,
     * `zip` or the `oth` parameter of a multi-prime RSA key.
     *
     * @since 1.0.0
     */
    UnsupportedAlgorithm,

    /**
     * The algorithm is known, but the allowlist of the caller or the crypto policy does not permit it.
     *
     * @since 1.0.0
     */
    AlgorithmNotAllowed,

    /**
     * The `crit` header lists an extension the caller does not understand or that is not used correctly.
     *
     * @since 1.0.0
     */
    UnknownCritical,

    /**
     * None of the keys of the caller fits the algorithm and the key id of the message.
     *
     * @since 1.0.0
     */
    KeyNotFound,

    /**
     * A key is well formed but unusable: the crypto policy refuses it, its private part does not belong to its public
     * part, or its certificate holds another key.
     *
     * @since 1.0.0
     */
    InvalidKey,

    /**
     * No signature verifies with the keys of the caller.
     *
     * @since 1.0.0
     */
    BadSignature,

    /**
     * The message does not decrypt. A wrong key, a wrong tag and a wrong padding all give this one failure, so there
     * is no oracle.
     *
     * @since 1.0.0
     */
    DecryptionFailed,

    /**
     * The `x5c` chain is missing or does not lead to a trust anchor.
     *
     * @since 1.0.0
     */
    UntrustedCertificate,

    /**
     * The token has another `typ` than the one expected.
     *
     * @since 1.0.0
     */
    WrongType,

    /**
     * The token is expired, or older than the maximum age.
     *
     * @since 1.0.0
     */
    Expired,

    /**
     * The token is not valid yet, or was issued in the future.
     *
     * @since 1.0.0
     */
    NotYetValid,

    /**
     * The token comes from another issuer.
     *
     * @since 1.0.0
     */
    WrongIssuer,

    /**
     * The token is meant for another audience, or names an audience where none is expected.
     *
     * @since 1.0.0
     */
    WrongAudience,

    /**
     * The token lacks a claim the validator requires.
     *
     * @since 1.0.0
     */
    MissingClaim,

    /**
     * The token is encrypted but not signed, and the validator requires a signature.
     *
     * @since 1.0.0
     */
    SignatureRequired,
}
