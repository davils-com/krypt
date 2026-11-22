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

package com.davils.krypt.acme

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import kotlinx.io.bytestring.ByteString

/**
 * An HTTP request of the ACME client, for an [AcmeTransport] to send.
 *
 * Values are immutable and safe to share between threads.
 *
 * @property method the method.
 * @property url the absolute URL.
 * @property headers the header fields the transport must send, such as `Content-Type` and `Accept`.
 * @property body the body, empty for `GET` and `HEAD`.
 * @constructor Describes a request.
 * @since 1.0.0
 */
public class AcmeRequest(
    public val method: AcmeMethod,
    public val url: String,
    public val headers: List<Pair<String, String>> = emptyList(),
    public val body: ByteString = ByteString(),
) {
    private val values: List<Any> get() = listOf(method, url, headers, body)

    /**
     * Returns the first value of the header field [name], ignoring the case of the name.
     *
     * @param name the field name.
     * @return the value, or null if the request has no such field.
     * @since 1.0.0
     */
    public fun header(name: String): String? =
        headers.firstOrNull { (field, _) -> field.equals(other = name, ignoreCase = true) }?.second

    /**
     * Compares every part.
     *
     * @param other the other object.
     * @return true if [other] is the same request.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeRequest && values == other.values

    /**
     * Hashes every part.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the method, the URL and the size of the body.
     *
     * @return the request as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeRequest(${method.methodName} ${SafeText.text(url)}, ${body.size} bytes)"
}
