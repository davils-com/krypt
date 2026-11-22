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

private const val PREFIX: String = "urn:ietf:params:acme:error:"

/**
 * The ACME error types of RFC 8555 section 6.7 and of RFC 9773.
 *
 * @property code the last part of the URN, such as `badNonce`.
 * @since 1.0.0
 */
public enum class AcmeProblemType(public val code: String) {
    /**
     * The request names an account that does not exist.
     *
     * @since 1.0.0
     */
    AccountDoesNotExist("accountDoesNotExist"),

    /**
     * The certificate of a new order was already replaced, by RFC 9773.
     *
     * @since 1.0.0
     */
    AlreadyReplaced("alreadyReplaced"),

    /**
     * The certificate is revoked already.
     *
     * @since 1.0.0
     */
    AlreadyRevoked("alreadyRevoked"),

    /**
     * The certification request is unacceptable.
     *
     * @since 1.0.0
     */
    BadCsr("badCSR"),

    /**
     * The nonce of the request is unacceptable; the client retries with a fresh one.
     *
     * @since 1.0.0
     */
    BadNonce("badNonce"),

    /**
     * The server does not accept the public key.
     *
     * @since 1.0.0
     */
    BadPublicKey("badPublicKey"),

    /**
     * The revocation reason is not allowed.
     *
     * @since 1.0.0
     */
    BadRevocationReason("badRevocationReason"),

    /**
     * The server does not accept the signature algorithm.
     *
     * @since 1.0.0
     */
    BadSignatureAlgorithm("badSignatureAlgorithm"),

    /**
     * A CAA record forbids the issuance.
     *
     * @since 1.0.0
     */
    Caa("caa"),

    /**
     * Several errors occurred; the subproblems name them.
     *
     * @since 1.0.0
     */
    Compound("compound"),

    /**
     * The server could not connect to the validation target.
     *
     * @since 1.0.0
     */
    Connection("connection"),

    /**
     * A DNS query failed during validation.
     *
     * @since 1.0.0
     */
    Dns("dns"),

    /**
     * The server requires an external account binding.
     *
     * @since 1.0.0
     */
    ExternalAccountRequired("externalAccountRequired"),

    /**
     * The response to a challenge was wrong.
     *
     * @since 1.0.0
     */
    IncorrectResponse("incorrectResponse"),

    /**
     * A contact URL of the account is invalid.
     *
     * @since 1.0.0
     */
    InvalidContact("invalidContact"),

    /**
     * The request is malformed.
     *
     * @since 1.0.0
     */
    Malformed("malformed"),

    /**
     * The order is not ready to be finalized.
     *
     * @since 1.0.0
     */
    OrderNotReady("orderNotReady"),

    /**
     * The request passes a rate limit; a `Retry-After` may say when to try again.
     *
     * @since 1.0.0
     */
    RateLimited("rateLimited"),

    /**
     * The server will not issue for the identifier.
     *
     * @since 1.0.0
     */
    RejectedIdentifier("rejectedIdentifier"),

    /**
     * The server failed internally.
     *
     * @since 1.0.0
     */
    ServerInternal("serverInternal"),

    /**
     * A TLS error occurred during validation.
     *
     * @since 1.0.0
     */
    Tls("tls"),

    /**
     * The client lacks the authorization for the request.
     *
     * @since 1.0.0
     */
    Unauthorized("unauthorized"),

    /**
     * A contact URL has a scheme the server does not support.
     *
     * @since 1.0.0
     */
    UnsupportedContact("unsupportedContact"),

    /**
     * The identifier is of a type the server does not support.
     *
     * @since 1.0.0
     */
    UnsupportedIdentifier("unsupportedIdentifier"),

    /**
     * The user has to act, such as agree to new terms of service, at the `instance` URL.
     *
     * @since 1.0.0
     */
    UserActionRequired("userActionRequired"),
    ;

    /**
     * The full URN, such as `urn:ietf:params:acme:error:badNonce`.
     *
     * @since 1.0.0
     */
    public val urn: String get() = PREFIX + code

    /**
     * Finds error types by their URN.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the error type whose URN is [urn].
         *
         * @param urn the `type` of a problem document.
         * @return the error type, or null if [urn] names no ACME error type.
         * @since 1.0.0
         */
        public fun of(urn: String): AcmeProblemType? = entries.firstOrNull { type -> type.urn == urn }
    }
}
