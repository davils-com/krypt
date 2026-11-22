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

package com.davils.krypt.ocsp

/**
 * Why an OCSP message could not be read or a response does not vouch for a certificate.
 *
 * @since 1.0.0
 */
public enum class OcspFailure {
    /**
     * The encoding is not valid DER of the structure, breaks a limit or carries a critical extension krypt does not
     * understand.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The responder answered with an error status instead of a signed response.
     *
     * @since 1.0.0
     */
    ResponderError,

    /**
     * The crypto policy forbids the algorithm of the signature, or krypt does not know it.
     *
     * @since 1.0.0
     */
    AlgorithmNotPermitted,

    /**
     * Neither the issuer nor a certificate in the response signed it.
     *
     * @since 1.0.0
     */
    BadSignature,

    /**
     * The response is signed by a certificate the issuer did not authorize to sign OCSP responses.
     *
     * @since 1.0.0
     */
    UnauthorizedResponder,

    /**
     * The response carries a nonce other than the one of the request, or none where one is required.
     *
     * @since 1.0.0
     */
    NonceMismatch,

    /**
     * The response says nothing about the certificate.
     *
     * @since 1.0.0
     */
    NotFound,

    /**
     * The status is not current at the time of verification.
     *
     * @since 1.0.0
     */
    Stale,
}
