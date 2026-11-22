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

package com.davils.krypt.keyset.kms

import com.davils.krypt.core.SecretBytes
import kotlinx.io.bytestring.ByteString

/**
 * A service that holds a key encryption key and encrypts small secrets with it, such as data keys and key sets.
 *
 * The application implements it over its key management service, such as HashiCorp Vault Transit, AWS KMS, Google
 * Cloud KMS, Azure Key Vault or an HSM; krypt never talks to a network itself. [LocalKms] and [KeysetKms] keep the key
 * in the process. An implementation must authenticate [encrypt]ed data together with its associated data, so that
 * [decrypt] refuses a ciphertext or a context that was changed.
 *
 * A failure of the service, such as a timeout, is thrown by the implementation and passed on to the caller.
 *
 * @since 1.0.0
 */
public interface KeyManagementService {
    /**
     * The name of the key encryption key, such as `aws-kms://arn:aws:kms:...`; it is stored with what the key
     * encrypts, so that a ciphertext of another key is told apart from a ciphertext that was changed.
     *
     * @since 1.0.0
     */
    public val keyUri: String

    /**
     * Encrypts [plaintext] and authenticates [associatedData] with it.
     *
     * @param plaintext the secret; the caller keeps and wipes it.
     * @param associatedData authenticated context that is not encrypted.
     * @return the ciphertext.
     * @since 1.0.0
     */
    public suspend fun encrypt(plaintext: SecretBytes, associatedData: ByteString): ByteString

    /**
     * Decrypts a ciphertext of [encrypt].
     *
     * @param ciphertext the ciphertext, possibly from an attacker.
     * @param associatedData the authenticated context it was encrypted with.
     * @return the secret, which the caller wipes, or null if the ciphertext is malformed or not authentic.
     * @since 1.0.0
     */
    public suspend fun decrypt(ciphertext: ByteString, associatedData: ByteString): SecretBytes?
}
