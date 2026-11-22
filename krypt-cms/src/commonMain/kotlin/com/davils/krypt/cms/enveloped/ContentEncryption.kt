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

package com.davils.krypt.cms.enveloped

/**
 * The content encryption algorithms krypt reads and writes in CMS.
 *
 * AES-CBC serves EnvelopedData and EncryptedData of RFC 5652, which are not authenticated: whoever changes the
 * ciphertext changes the plaintext unnoticed. AES-GCM serves AuthEnvelopedData of RFC 5083 with the parameters of
 * RFC 5084, a nonce of 12 bytes and a tag of 16 bytes; prefer it.
 *
 * @property keyBytes the size of the content-encryption key.
 * @property isAuthenticated true for AES-GCM, which only AuthEnvelopedData carries.
 * @since 1.0.0
 */
public enum class ContentEncryption(public val keyBytes: Int, public val isAuthenticated: Boolean) {
    /**
     * AES-128 in CBC mode with PKCS #7 padding.
     *
     * @since 1.0.0
     */
    Aes128Cbc(keyBytes = 16, isAuthenticated = false),

    /**
     * AES-256 in CBC mode with PKCS #7 padding.
     *
     * @since 1.0.0
     */
    Aes256Cbc(keyBytes = 32, isAuthenticated = false),

    /**
     * AES-128-GCM with a nonce of 12 bytes and a tag of 16 bytes.
     *
     * @since 1.0.0
     */
    Aes128Gcm(keyBytes = 16, isAuthenticated = true),

    /**
     * AES-256-GCM with a nonce of 12 bytes and a tag of 16 bytes.
     *
     * @since 1.0.0
     */
    Aes256Gcm(keyBytes = 32, isAuthenticated = true),
}
