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
 * The status of an OCSP response by RFC 6960.
 *
 * @property code the value of OCSPResponseStatus.
 * @since 1.0.0
 */
public enum class OcspResponseStatus(public val code: Int) {
    /**
     * The response carries a signed answer.
     *
     * @since 1.0.0
     */
    Successful(code = 0),

    /**
     * The request was not valid.
     *
     * @since 1.0.0
     */
    MalformedRequest(code = 1),

    /**
     * The responder failed.
     *
     * @since 1.0.0
     */
    InternalError(code = 2),

    /**
     * The responder cannot answer now.
     *
     * @since 1.0.0
     */
    TryLater(code = 3),

    /**
     * The responder answers only signed requests.
     *
     * @since 1.0.0
     */
    SignatureRequired(code = 5),

    /**
     * The responder does not answer for the certificate.
     *
     * @since 1.0.0
     */
    Unauthorized(code = 6),
}
