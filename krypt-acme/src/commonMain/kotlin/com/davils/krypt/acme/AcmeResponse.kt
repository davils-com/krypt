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

package com.davils.krypt.acme

import kotlinx.io.bytestring.ByteString

private const val LOWEST_STATUS: Int = 100
private const val HIGHEST_STATUS: Int = 599

/**
 * An HTTP response an [AcmeTransport] hands back to the ACME client.
 *
 * Every part may come from an attacker: the client checks the sizes against its [AcmeLimits] before it reads
 * anything. Values are immutable and safe to share between threads.
 *
 * @property status the status code, 100 to 599.
 * @property headers the header fields in order; a field that occurs several times occurs as several pairs.
 * @property body the body, as received.
 * @constructor Describes a response.
 * @throws IllegalArgumentException if [status] is not 100 to 599.
 * @since 1.0.0
 */
public class AcmeResponse(
    public val status: Int,
    public val headers: List<Pair<String, String>> = emptyList(),
    public val body: ByteString = ByteString(),
) {
    private val values: List<Any> get() = listOf(status, headers, body)

    init {
        require(status in LOWEST_STATUS..HIGHEST_STATUS) { "An HTTP status is 100 to 599" }
    }

    /**
     * Returns every value of the header field [name], ignoring the case of the name.
     *
     * @param name the field name.
     * @return the values in order, empty if the response has no such field.
     * @since 1.0.0
     */
    public fun headers(name: String): List<String> = headers.mapNotNull { (field, value) ->
        value.takeIf { field.equals(other = name, ignoreCase = true) }
    }

    /**
     * Compares every part.
     *
     * @param other the other object.
     * @return true if [other] is the same response.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeResponse && values == other.values

    /**
     * Hashes every part.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the status and the sizes, never the content.
     *
     * @return the response as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AcmeResponse($status, ${headers.size} headers, ${body.size} bytes)"
}
