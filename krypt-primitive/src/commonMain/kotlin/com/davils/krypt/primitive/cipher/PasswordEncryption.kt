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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.primitive.cipher

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.SecretText
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.internal.Pbes2
import com.davils.krypt.primitive.key.KeyFailure
import kotlinx.io.bytestring.ByteString

/**
 * Password-based encryption of PKCS #5 (PBES2 with PBKDF2 and AES-CBC) for formats that need it, such as PKCS #12
 * and CMS; it is no authenticated encryption, so the format must protect the integrity, as the MAC of PKCS #12 does.
 *
 * Iterations are checked against the crypto policy in both directions.
 *
 * @since 1.0.0
 */
@DavilsInternal
public object PasswordEncryption {
    /**
     * Encrypts [plaintext] with a key derived from [password].
     *
     * @param crypto the primitives.
     * @param plaintext the content.
     * @param password the password.
     * @param iterations the iterations of PBKDF2.
     * @return the DER of the AlgorithmIdentifier of PBES2 and the ciphertext.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [iterations].
     * @since 1.0.0
     */
    public suspend fun encrypt(
        crypto: Crypto,
        plaintext: SecretBytes,
        password: SecretText,
        iterations: Int,
    ): Pair<ByteString, ByteString> =
        Pbes2.encryptParts(crypto = crypto, plaintext = plaintext, password = password, iterations = iterations)

    /**
     * Decrypts what [encrypt] encrypted.
     *
     * @param crypto the primitives.
     * @param algorithm the DER of the AlgorithmIdentifier, possibly from an attacker.
     * @param ciphertext the ciphertext.
     * @param password the password.
     * @return the content, or why it could not be decrypted.
     * @since 1.0.0
     */
    public suspend fun decrypt(
        crypto: Crypto,
        algorithm: ByteString,
        ciphertext: ByteString,
        password: SecretText,
    ): Outcome<SecretBytes, KeyFailure> =
        Pbes2.decryptParts(crypto = crypto, algorithm = algorithm, ciphertext = ciphertext, password = password)
}
