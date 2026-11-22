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

package com.davils.krypt.keystore

/**
 * Why a key store could not be read.
 *
 * @since 1.0.0
 */
public enum class KeystoreFailure {
    /**
     * The bytes are not a key store krypt reads, they break a limit, or a key comes without its certificate.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The password is wrong, or the key store was changed.
     *
     * @since 1.0.0
     */
    WrongPassword,

    /**
     * The key store uses a protection krypt does not read, such as the legacy algorithms of PKCS #12 with SHA-1,
     * 3DES or RC2, a public-key integrity mode or no MAC at all; convert it, for example with
     * `openssl pkcs12 -export -keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256`.
     *
     * @since 1.0.0
     */
    Unsupported,

    /**
     * The crypto policy or the limits forbid what the key store asks for, such as too many or too few iterations,
     * a weak key or a forbidden algorithm.
     *
     * @since 1.0.0
     */
    Refused,
}
