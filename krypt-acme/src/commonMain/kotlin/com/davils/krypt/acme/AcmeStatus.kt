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

/**
 * The status of an ACME account, order, authorization or challenge, by RFC 8555 section 7.1.6.
 *
 * @property statusName the name in JSON.
 * @since 1.0.0
 */
public enum class AcmeStatus(public val statusName: String) {
    /**
     * Waiting: for an order its authorizations, for an authorization and a challenge the validation.
     *
     * @since 1.0.0
     */
    Pending("pending"),

    /**
     * An order whose authorizations are valid, ready to be finalized.
     *
     * @since 1.0.0
     */
    Ready("ready"),

    /**
     * An order being issued or a challenge being validated.
     *
     * @since 1.0.0
     */
    Processing("processing"),

    /**
     * Done: the account is usable, the order issued, the authorization or the challenge succeeded.
     *
     * @since 1.0.0
     */
    Valid("valid"),

    /**
     * Failed for good.
     *
     * @since 1.0.0
     */
    Invalid("invalid"),

    /**
     * An account or an authorization its holder deactivated.
     *
     * @since 1.0.0
     */
    Deactivated("deactivated"),

    /**
     * An authorization past its expiry.
     *
     * @since 1.0.0
     */
    Expired("expired"),

    /**
     * An account or an authorization the server revoked.
     *
     * @since 1.0.0
     */
    Revoked("revoked"),
    ;

    /**
     * Finds statuses by name.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns the status named [name].
         *
         * @param name the name in JSON.
         * @return the status, or null if [name] names none.
         * @since 1.0.0
         */
        public fun of(name: String): AcmeStatus? = entries.firstOrNull { status -> status.statusName == name }
    }
}
