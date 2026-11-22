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

package com.davils.krypt.spiffe.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.SpiffeIdFailure
import com.davils.krypt.spiffe.TrustDomain

internal object IdParser {
    const val PREFIX: String = "spiffe://"

    const val SLASH: Char = '/'

    private const val SYMBOLS: String = ".-_"

    private const val DOT: String = "."

    private const val DOTS: String = ".."

    private val DOMAIN_SPECIALS: Map<Char, SpiffeIdFailure> = mapOf(
        '%' to SpiffeIdFailure.PercentEncoded,
        '@' to SpiffeIdFailure.UserInfo,
        ':' to SpiffeIdFailure.Port,
        '?' to SpiffeIdFailure.Query,
        '#' to SpiffeIdFailure.Fragment,
    )

    private val PATH_SPECIALS: Map<Char, SpiffeIdFailure> = mapOf(
        '%' to SpiffeIdFailure.PercentEncoded,
        '?' to SpiffeIdFailure.Query,
        '#' to SpiffeIdFailure.Fragment,
    )

    fun parse(text: String): Outcome<SpiffeId, SpiffeIdFailure> {
        val failure = failureOf(text)
        if (failure != null) return Outcome.Failure(failure)
        val (name, path) = split(text.substring(startIndex = PREFIX.length))
        return Outcome.Success(SpiffeId(CheckedId(trustDomain = TrustDomain(CheckedDomain(name)), path = path)))
    }

    fun trustDomainFailure(name: String): SpiffeIdFailure? =
        SpiffeIdFailure.MissingTrustDomain.takeIf { name.isEmpty() }
            ?: SpiffeIdFailure.TrustDomainTooLong.takeIf { name.length > TrustDomain.MAXIMUM_LENGTH }
            ?: name.firstNotNullOfOrNull { char -> domainCharacterFailure(char) }

    fun segmentFailure(segment: String, isLast: Boolean): SpiffeIdFailure? =
        SpiffeIdFailure.TrailingSlash.takeIf { segment.isEmpty() && isLast }
            ?: SpiffeIdFailure.EmptySegment.takeIf { segment.isEmpty() }
            ?: SpiffeIdFailure.DotSegment.takeIf { segment == DOT || segment == DOTS }
            ?: segment.firstNotNullOfOrNull { char -> pathCharacterFailure(char) }

    private fun failureOf(text: String): SpiffeIdFailure? = SpiffeIdFailure.Empty.takeIf { text.isEmpty() }
        ?: SpiffeIdFailure.TooLong.takeIf { text.length > SpiffeId.MAXIMUM_LENGTH }
        ?: SpiffeIdFailure.WrongScheme.takeUnless { text.startsWith(PREFIX) }
        ?: partsFailure(text.substring(startIndex = PREFIX.length))

    private fun partsFailure(rest: String): SpiffeIdFailure? {
        val (name, path) = split(rest)
        return trustDomainFailure(name) ?: pathFailure(path)
    }

    private fun split(rest: String): Pair<String, String> {
        val end = rest.indexOf(SLASH).takeIf { index -> index >= 0 } ?: rest.length
        return rest.substring(startIndex = 0, endIndex = end) to rest.substring(startIndex = end)
    }

    private fun pathFailure(path: String): SpiffeIdFailure? {
        if (path.isEmpty()) return null
        val segments = path.substring(startIndex = 1).split(SLASH)
        val last = segments.lastIndex
        return segments.withIndex().firstNotNullOfOrNull { (index, segment) ->
            segmentFailure(segment = segment, isLast = index == last)
        }
    }

    private fun domainCharacterFailure(char: Char): SpiffeIdFailure? {
        val isAllowed = char in 'a'..'z' || char in '0'..'9' || char in SYMBOLS
        if (isAllowed) return null
        return DOMAIN_SPECIALS[char] ?: SpiffeIdFailure.BadTrustDomainCharacter
    }

    private fun pathCharacterFailure(char: Char): SpiffeIdFailure? {
        val isAllowed = char in 'a'..'z' || char in 'A'..'Z' || char in '0'..'9' || char in SYMBOLS
        if (isAllowed) return null
        return PATH_SPECIALS[char] ?: SpiffeIdFailure.BadPathCharacter
    }
}
