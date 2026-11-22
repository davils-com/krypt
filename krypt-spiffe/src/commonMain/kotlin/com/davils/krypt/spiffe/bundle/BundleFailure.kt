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

package com.davils.krypt.spiffe.bundle

/**
 * Why a SPIFFE bundle or bundle map was refused.
 *
 * @since 1.0.0
 */
public enum class BundleFailure {
    /**
     * The text is no JSON object of the format: invalid JSON, a duplicate member, `keys` or `trust_domains` missing
     * or of the wrong type, or a sequence or refresh hint that is no non-negative integer.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The text, the keys or the trust domains exceed their limits.
     *
     * @since 1.0.0
     */
    LimitExceeded,

    /**
     * A key for `x509-svid` or `jwt-svid` is invalid: its parameters, its certificate, a private or symmetric key,
     * or a key the crypto policy refuses.
     *
     * @since 1.0.0
     */
    InvalidKey,

    /**
     * A key for `jwt-svid` has no `kid`, which section 6.1 of the JWT-SVID specification requires.
     *
     * @since 1.0.0
     */
    MissingKeyId,

    /**
     * Two keys for `jwt-svid` share a `kid`.
     *
     * @since 1.0.0
     */
    DuplicateKeyId,

    /**
     * A name of a bundle map is no trust domain name.
     *
     * @since 1.0.0
     */
    InvalidTrustDomain,
}
