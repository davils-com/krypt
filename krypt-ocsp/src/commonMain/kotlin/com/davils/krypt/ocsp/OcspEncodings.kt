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

package com.davils.krypt.ocsp

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.encoding.Base64
import kotlinx.io.bytestring.ByteString

/**
 * The transport of OCSP over HTTP by RFC 6960 and RFC 9919, without any HTTP.
 *
 * By POST, the body is [OcspRequest.encoded] with the content type [REQUEST_MEDIA_TYPE]. By GET, the request is
 * appended to the URL of the responder as one path segment: its encoding in Base64 with the characters `+`, `/` and
 * `=` escaped. A GET request may be cached on the way, so it suits requests without a nonce. The answer has the
 * content type [RESPONSE_MEDIA_TYPE].
 *
 * @since 1.0.0
 */
public object OcspEncodings {
    /**
     * The media type of a request.
     *
     * @since 1.0.0
     */
    public const val REQUEST_MEDIA_TYPE: String = "application/ocsp-request"

    /**
     * The media type of a response.
     *
     * @since 1.0.0
     */
    public const val RESPONSE_MEDIA_TYPE: String = "application/ocsp-response"

    /**
     * The longest URL of a GET request by RFC 9919; longer requests go by POST.
     *
     * @since 1.0.0
     */
    public const val MAXIMUM_GET_LENGTH: Int = 255

    private const val PERCENT: Char = '%'
    private const val ESCAPE_LENGTH: Int = 3
    private const val SEPARATOR: String = "/"
    private val ESCAPES: Map<Char, String> = mapOf('+' to "%2B", '/' to "%2F", '=' to "%3D")
    private val UNESCAPES: Map<String, Char> = ESCAPES.entries.associate { (char, escape) -> escape to char }

    /**
     * Returns the path segment of [request] for a GET request.
     *
     * @param request the request.
     * @return the segment.
     * @since 1.0.0
     */
    public fun pathSegment(request: OcspRequest): String {
        val text = Base64.encode(request.encoded)
        return buildString { text.forEach { char -> append(ESCAPES[char] ?: char) } }
    }

    /**
     * Returns the URL of a GET request for [request] to the responder at [responderUrl].
     *
     * @param responderUrl the URL of the responder, such as one from the authority information access of a
     *   certificate; a trailing slash is not doubled.
     * @param request the request.
     * @return the URL.
     * @since 1.0.0
     */
    public fun getUrl(responderUrl: String, request: OcspRequest): String =
        responderUrl.removeSuffix(SEPARATOR) + SEPARATOR + pathSegment(request)

    /**
     * Tells whether [request] fits a GET request to [responderUrl] by RFC 9919.
     *
     * @param responderUrl the URL of the responder.
     * @param request the request.
     * @return true if the URL has at most [MAXIMUM_GET_LENGTH] characters.
     * @since 1.0.0
     */
    public fun isGetSuitable(responderUrl: String, request: OcspRequest): Boolean =
        getUrl(responderUrl, request).length <= MAXIMUM_GET_LENGTH

    /**
     * Reads the encoding of a request from the path segment of a GET request, as a responder does.
     *
     * The escapes `%2B`, `%2F` and `%3D` are read in either case, and the characters themselves are accepted, as
     * some clients do not escape them. Every other escape and every non-canonical Base64 is refused.
     *
     * @param segment the path segment, possibly from an attacker.
     * @return the encoding, to read with [Ocsp.decodeRequest], or [OcspFailure.Malformed].
     * @since 1.0.0
     */
    public fun requestOf(segment: String): Outcome<ByteString, OcspFailure> {
        val text = StringBuilder(segment.length)
        var index = 0
        while (index < segment.length) {
            val char = segment[index]
            val isEscape = char == PERCENT
            val escaped = segment.takeIf { isEscape }?.let { value -> unescape(value, index) }
            text.append(escaped ?: char)
            index += listOf(1, ESCAPE_LENGTH)[isEscape.compareTo(false)]
        }
        val decoded = Base64.decode(text).getOrNull()
        val success = decoded?.let { found -> Outcome.Success(found) }
        return success ?: Outcome.Failure(OcspFailure.Malformed)
    }

    private fun unescape(segment: String, at: Int): Char? {
        val end = minOf(a = at + ESCAPE_LENGTH, b = segment.length)
        val escape = segment.substring(startIndex = at, endIndex = end)
        return UNESCAPES[escape.uppercase()]
    }
}
