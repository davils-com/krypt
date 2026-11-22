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

import com.davils.krypt.acme.AcmeError

internal object Urls {
    private const val HTTPS: String = "https://"
    private const val HTTP: String = "http://"
    private const val LOWEST_VISIBLE: Char = '!'
    private const val HIGHEST_VISIBLE: Char = '~'
    private val AUTHORITY_ENDS: CharArray = charArrayOf('/', '?')

    fun checked(text: String, isHttpAllowed: Boolean, maximumLength: Int): String {
        refuseUnless(condition = text.length <= maximumLength, error = AcmeError.LimitExceeded)
        val isHttp = isHttpAllowed && text.startsWith(HTTP)
        refuseUnless(condition = text.startsWith(HTTPS) || isHttp, error = AcmeError.InsecureUrl)
        val rest = text.substringAfter(delimiter = "://")
        val authority = rest.takeWhile { char -> char !in AUTHORITY_ENDS }
        val isVisible = text.all { char -> char in LOWEST_VISIBLE..HIGHEST_VISIBLE }
        refuseUnless(isVisible && authority.isNotEmpty() && '@' !in authority && '#' !in text)
        return text
    }
}
