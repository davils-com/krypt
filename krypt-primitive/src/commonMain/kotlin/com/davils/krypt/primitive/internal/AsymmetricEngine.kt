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

package com.davils.krypt.primitive.internal

import com.davils.krypt.core.algorithm.AsymmetricEncryptionAlgorithm
import com.davils.krypt.core.algorithm.KemAlgorithm
import com.davils.krypt.core.algorithm.KeyAgreementAlgorithm
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey

internal interface AsymmetricEngine {
    suspend fun generate(type: KeyType): KeyPair

    suspend fun sign(algorithm: SignatureAlgorithm, key: PrivateKey, data: ByteArray): ByteArray

    suspend fun verify(algorithm: SignatureAlgorithm, key: PublicKey, data: ByteArray, signature: ByteArray): Boolean

    suspend fun agree(algorithm: KeyAgreementAlgorithm, privateKey: PrivateKey, publicKey: PublicKey): ByteArray

    suspend fun encapsulate(algorithm: KemAlgorithm, publicKey: PublicKey): Pair<ByteArray, ByteArray>

    suspend fun decapsulate(algorithm: KemAlgorithm, privateKey: PrivateKey, encapsulated: ByteArray): ByteArray?

    suspend fun encrypt(algorithm: AsymmetricEncryptionAlgorithm, publicKey: PublicKey, data: ByteArray): ByteArray

    suspend fun decrypt(algorithm: AsymmetricEncryptionAlgorithm, privateKey: PrivateKey, data: ByteArray): ByteArray?
}
