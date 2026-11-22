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

package com.davils.krypt.x509.extension

/**
 * One bit of the key usage extension.
 *
 * @property bit the position of the bit.
 * @since 1.0.0
 */
public enum class KeyUsage(public val bit: Int) {
    /**
     * Signatures other than on certificates and revocation lists.
     *
     * @since 1.0.0
     */
    DigitalSignature(bit = 0),

    /**
     * Signatures that commit to content, formerly non-repudiation.
     *
     * @since 1.0.0
     */
    ContentCommitment(bit = 1),

    /**
     * Encrypting keys with RSA.
     *
     * @since 1.0.0
     */
    KeyEncipherment(bit = 2),

    /**
     * Encrypting data with the public key directly.
     *
     * @since 1.0.0
     */
    DataEncipherment(bit = 3),

    /**
     * Key agreement.
     *
     * @since 1.0.0
     */
    KeyAgreement(bit = 4),

    /**
     * Signing certificates.
     *
     * @since 1.0.0
     */
    KeyCertSign(bit = 5),

    /**
     * Signing revocation lists.
     *
     * @since 1.0.0
     */
    CrlSign(bit = 6),

    /**
     * Encrypting only in a key agreement.
     *
     * @since 1.0.0
     */
    EncipherOnly(bit = 7),

    /**
     * Decrypting only in a key agreement.
     *
     * @since 1.0.0
     */
    DecipherOnly(bit = 8),
}
