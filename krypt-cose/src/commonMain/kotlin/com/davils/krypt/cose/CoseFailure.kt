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

package com.davils.krypt.cose

/**
 * Why a COSE message or a COSE_Key was refused.
 *
 * @since 1.0.0
 */
public enum class CoseFailure {
    /**
     * The encoding is not the CBOR of the structure: not well formed, not deterministic where that is required,
     * beyond a limit, of the wrong tag, with a header parameter of the wrong type, with a label in both header buckets,
     * or with a payload that is both detached and given, or neither.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The `crit` header parameter names a label that neither krypt nor the application processes.
     *
     * @since 1.0.0
     */
    UnknownCritical,

    /**
     * The algorithm of the message is missing, unknown to krypt, outside the allowlist of the call, forbidden by the
     * crypto policy or not available on the platform.
     *
     * @since 1.0.0
     */
    AlgorithmNotPermitted,

    /**
     * A COSE_Key has a key type, a curve, an algorithm or an operation krypt does not implement, a compressed point,
     * more than two primes, or material the crypto policy refuses.
     *
     * @since 1.0.0
     */
    UnsupportedKey,

    /**
     * None of the keys given fits the algorithm, the key id and the operation of the message.
     *
     * @since 1.0.0
     */
    KeyNotFound,

    /**
     * No signature verifies with the keys that fit.
     *
     * @since 1.0.0
     */
    InvalidSignature,

    /**
     * No MAC verifies with the keys that fit.
     *
     * @since 1.0.0
     */
    InvalidTag,

    /**
     * The content could not be decrypted: no key fits, a key does not unwrap or derive the content key, or the tag of
     * the content does not verify. Every such cause gives this one failure, so that it reveals nothing.
     *
     * @since 1.0.0
     */
    DecryptionFailed,
}
