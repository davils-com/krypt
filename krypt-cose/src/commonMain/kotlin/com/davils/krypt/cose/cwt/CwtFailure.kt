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

package com.davils.krypt.cose.cwt

/**
 * Why a CWT was refused: a failure of its COSE layers or of its claims.
 *
 * @since 1.0.0
 */
public enum class CwtFailure {
    /**
     * The CWT is not a well-formed COSE message of a type the validation accepts, nests too deeply, or its claims
     * are not a map of claims of their types.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * A `crit` header parameter names a label nobody processes.
     *
     * @since 1.0.0
     */
    UnknownCritical,

    /**
     * An algorithm of the CWT is outside the allowlist of the validation or forbidden by the crypto policy.
     *
     * @since 1.0.0
     */
    AlgorithmNotPermitted,

    /**
     * A COSE_Key in the CWT is not supported.
     *
     * @since 1.0.0
     */
    UnsupportedKey,

    /**
     * None of the keys given fits the CWT.
     *
     * @since 1.0.0
     */
    KeyNotFound,

    /**
     * The signature does not verify.
     *
     * @since 1.0.0
     */
    InvalidSignature,

    /**
     * The MAC does not verify.
     *
     * @since 1.0.0
     */
    InvalidTag,

    /**
     * The CWT could not be decrypted.
     *
     * @since 1.0.0
     */
    DecryptionFailed,

    /**
     * No layer of the CWT authenticates its issuer, for example because its only protection is an encryption to an
     * ECDH-ES recipient; see [CwtValidation.isAuthenticationRequired].
     *
     * @since 1.0.0
     */
    Unauthenticated,

    /**
     * The expiration time has passed, beyond the clock skew.
     *
     * @since 1.0.0
     */
    Expired,

    /**
     * The not-before time has not come, beyond the clock skew.
     *
     * @since 1.0.0
     */
    NotYetValid,

    /**
     * The issued-at time lies in the future, beyond the clock skew.
     *
     * @since 1.0.0
     */
    IssuedInFuture,

    /**
     * The issuer is not the one the validation expects.
     *
     * @since 1.0.0
     */
    WrongIssuer,

    /**
     * The audience does not name the one the validation expects.
     *
     * @since 1.0.0
     */
    WrongAudience,

    /**
     * A claim the validation requires is missing.
     *
     * @since 1.0.0
     */
    MissingClaim,
}
