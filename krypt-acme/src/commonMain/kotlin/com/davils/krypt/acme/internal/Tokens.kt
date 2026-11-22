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

package com.davils.krypt.acme.internal

internal object Tokens {
    const val MINIMUM_TOKEN: Int = 22
    const val MAXIMUM_TOKEN: Int = 256
    const val MAXIMUM_NONCE: Int = 512
    private const val PERIOD: Char = '.'

    fun isValid(token: String): Boolean = token.length in MINIMUM_TOKEN..MAXIMUM_TOKEN && isBase64Url(token)

    fun isNonce(nonce: String): Boolean = nonce.length in 1..MAXIMUM_NONCE && isBase64Url(nonce)

    fun isCertificateId(text: String): Boolean {
        val parts = text.split(PERIOD)
        val isShaped = parts.size == 2 && text.length <= MAXIMUM_NONCE
        return isShaped && parts.all { part -> part.isNotEmpty() && isBase64Url(part) }
    }

    private fun isBase64Url(text: String): Boolean = text.all { char -> isBase64UrlChar(char) }

    private fun isBase64UrlChar(char: Char): Boolean =
        char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9' || char == '-' || char == '_'
}
