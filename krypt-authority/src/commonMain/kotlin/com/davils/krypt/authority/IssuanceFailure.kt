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

package com.davils.krypt.authority

/**
 * Why a certificate authority refused to issue a certificate.
 *
 * @since 1.0.0
 */
public enum class IssuanceFailure {
    /**
     * The request is not valid, such as a certification request whose signature does not verify or name
     * constraints for a certificate that is no authority.
     *
     * @since 1.0.0
     */
    InvalidRequest,

    /**
     * The issuance policy forbids the key of the subject, or krypt cannot read it.
     *
     * @since 1.0.0
     */
    KeyNotPermitted,

    /**
     * A name is missing, of a kind the profile does not allow or outside what the issuance policy permits.
     *
     * @since 1.0.0
     */
    NameNotPermitted,

    /**
     * The validity is longer than the profile or the policy allows, ends after the authority, or the authority is
     * not valid now.
     *
     * @since 1.0.0
     */
    ValidityNotPermitted,

    /**
     * The authority may not issue the profile, such as an authority with a path length of zero asked for another
     * authority.
     *
     * @since 1.0.0
     */
    ProfileNotPermitted,

    /**
     * The repository refused every fresh serial number as taken; with 159 random bits this means the repository is
     * broken.
     *
     * @since 1.0.0
     */
    SerialConflict,
}
