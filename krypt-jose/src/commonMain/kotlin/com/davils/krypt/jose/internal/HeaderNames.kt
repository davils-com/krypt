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

internal object HeaderNames {
    const val ALGORITHM: String = "alg"
    const val ENCRYPTION: String = "enc"
    const val KEY_ID: String = "kid"
    const val TYPE: String = "typ"
    const val CONTENT_TYPE: String = "cty"
    const val CRITICAL: String = "crit"
    const val BASE64: String = "b64"
    const val COMPRESSION: String = "zip"
    const val EPHEMERAL_KEY: String = "epk"
    const val PARTY_U: String = "apu"
    const val PARTY_V: String = "apv"
    const val IV: String = "iv"
    const val TAG: String = "tag"
    const val SALT: String = "p2s"
    const val COUNT: String = "p2c"
    const val CHAIN: String = "x5c"
    const val CHAIN_URL: String = "x5u"
    const val SHA1_THUMBPRINT: String = "x5t"
    const val SHA256_THUMBPRINT: String = "x5t#S256"
    const val KEY_SET_URL: String = "jku"
    const val KEY: String = "jwk"

    val TEXTS: Set<String> = setOf(
        ALGORITHM,
        ENCRYPTION,
        KEY_ID,
        TYPE,
        CONTENT_TYPE,
        COMPRESSION,
        PARTY_U,
        PARTY_V,
        IV,
        TAG,
        SALT,
        CHAIN_URL,
        SHA1_THUMBPRINT,
        SHA256_THUMBPRINT,
        KEY_SET_URL,
    )

    val REGISTERED: Set<String> = TEXTS + setOf(CRITICAL, EPHEMERAL_KEY, COUNT, CHAIN, KEY)
}
