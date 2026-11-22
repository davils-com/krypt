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

package com.davils.krypt.jose.internal

import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey

private const val BYTE_BITS: Int = 8

internal fun isPairOf(privateKey: PrivateKey, publicKey: PublicKey): Boolean =
    privateKey.family == publicKey.family && privateKey.curve == publicKey.curve

internal fun rsaKey(key: JoseKey): PrivateKey? =
    (key as? JoseKey.Private)?.let { found -> found.key.takeIf { found.key.family == KeyFamily.Rsa } }

internal fun fittingSecret(key: JoseKey, bytes: Int): SecretKey? =
    (key as? JoseKey.Secret)?.let { found -> found.key.takeIf { found.key.bits == bytes * BYTE_BITS } }
