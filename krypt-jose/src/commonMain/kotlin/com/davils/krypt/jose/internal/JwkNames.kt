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

internal object JwkNames {
    const val TYPE: String = "kty"
    const val CURVE: String = "crv"
    const val X: String = "x"
    const val Y: String = "y"
    const val D: String = "d"
    const val N: String = "n"
    const val E: String = "e"
    const val P: String = "p"
    const val Q: String = "q"
    const val DP: String = "dp"
    const val DQ: String = "dq"
    const val QI: String = "qi"
    const val K: String = "k"
    const val OTHER_PRIMES: String = "oth"
    const val USE: String = "use"
    const val OPERATIONS: String = "key_ops"
    const val ALGORITHM: String = "alg"
    const val KEY_ID: String = "kid"
    const val CHAIN: String = "x5c"
    const val CHAIN_URL: String = "x5u"
    const val SHA1_THUMBPRINT: String = "x5t"
    const val SHA256_THUMBPRINT: String = "x5t#S256"
    const val KEYS: String = "keys"

    val RSA_PRIVATE: List<String> = listOf(D, P, Q, DP, DQ, QI)

    val KEY_PARAMETERS: Set<String> = setOf(CURVE, X, Y, N, E, K, OTHER_PRIMES) + RSA_PRIVATE

    val KNOWN: Set<String> = KEY_PARAMETERS + setOf(TYPE, USE, OPERATIONS, ALGORITHM, KEY_ID, CHAIN)

    val TEXTS: List<String> = listOf(CHAIN_URL, SHA1_THUMBPRINT, SHA256_THUMBPRINT)
}
