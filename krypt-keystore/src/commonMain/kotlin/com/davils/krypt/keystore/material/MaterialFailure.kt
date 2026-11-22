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

package com.davils.krypt.keystore.material

/**
 * Why key material could not be loaded.
 *
 * @since 1.0.0
 */
public enum class MaterialFailure {
    /**
     * Nothing exists under a reference.
     *
     * @since 1.0.0
     */
    Missing,

    /**
     * The source could not be read now.
     *
     * @since 1.0.0
     */
    Unavailable,

    /**
     * The material is larger than the limits allow.
     *
     * @since 1.0.0
     */
    TooLarge,

    /**
     * The material is no PKCS #12 file, PEM text or certificate krypt reads.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The password is wrong, missing for an encrypted key, or the material was changed.
     *
     * @since 1.0.0
     */
    WrongPassword,

    /**
     * The material uses an algorithm or a protection krypt does not read.
     *
     * @since 1.0.0
     */
    Unsupported,

    /**
     * The crypto policy or the limits forbid what the material asks for.
     *
     * @since 1.0.0
     */
    Refused,

    /**
     * The material holds no private key, or none under the alias asked for.
     *
     * @since 1.0.0
     */
    NoKey,

    /**
     * The material holds several private keys and no alias chose one.
     *
     * @since 1.0.0
     */
    AmbiguousKey,

    /**
     * The material holds no certificate.
     *
     * @since 1.0.0
     */
    NoCertificate,

    /**
     * No certificate belongs to the private key.
     *
     * @since 1.0.0
     */
    KeyMismatch,
}
