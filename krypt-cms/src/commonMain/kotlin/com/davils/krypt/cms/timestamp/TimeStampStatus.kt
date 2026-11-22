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

package com.davils.krypt.cms.timestamp

/**
 * The PKIStatus of a time-stamp response by RFC 3161.
 *
 * @property code the value of PKIStatus.
 * @property isGranted true if the response carries a token.
 * @since 1.0.0
 */
public enum class TimeStampStatus(public val code: Int, public val isGranted: Boolean) {
    /**
     * The token is granted as requested.
     *
     * @since 1.0.0
     */
    Granted(code = 0, isGranted = true),

    /**
     * The token is granted with modifications.
     *
     * @since 1.0.0
     */
    GrantedWithModifications(code = 1, isGranted = true),

    /**
     * The request is rejected.
     *
     * @since 1.0.0
     */
    Rejection(code = 2, isGranted = false),

    /**
     * The request is not processed yet.
     *
     * @since 1.0.0
     */
    Waiting(code = 3, isGranted = false),

    /**
     * A revocation of the authority is imminent.
     *
     * @since 1.0.0
     */
    RevocationWarning(code = 4, isGranted = false),

    /**
     * The authority has been revoked.
     *
     * @since 1.0.0
     */
    RevocationNotification(code = 5, isGranted = false),
}
