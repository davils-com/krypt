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

import com.davils.krypt.core.algorithm.Algorithm
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.CryptoException
import com.davils.krypt.primitive.UnsupportedAlgorithmException

internal fun platformRefusal(): CryptoException = CryptoException("The platform refused the key or the input")

internal suspend fun Crypto.requireSupported(algorithm: Algorithm) {
    if (!capabilities.supports(algorithm)) throw UnsupportedAlgorithmException(algorithm.algorithmName)
}
