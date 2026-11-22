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

package com.davils.krypt.primitive.key

/**
 * Why bytes or text could not be read as a key.
 *
 * @since 1.0.0
 */
public enum class KeyFailure {
    /**
     * The input is not a well-formed encoding of a key.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The key uses an algorithm or a curve krypt does not know.
     *
     * @since 1.0.0
     */
    UnsupportedAlgorithm,

    /**
     * The key is well formed, but the crypto policy forbids it, such as an RSA key below the minimum size or a curve
     * the policy does not permit.
     *
     * @since 1.0.0
     */
    Refused,

    /**
     * The key is encrypted and no password was given.
     *
     * @since 1.0.0
     */
    PasswordRequired,

    /**
     * The password does not decrypt the key, or the encrypted key was tampered with; the two are indistinguishable
     * on purpose.
     *
     * @since 1.0.0
     */
    WrongPassword,

    /**
     * The key is encrypted with a scheme krypt does not read, such as the legacy encryption of OpenSSL in PEM
     * headers or a PBES2 cipher other than AES-CBC.
     *
     * @since 1.0.0
     */
    UnsupportedEncryption,
}
