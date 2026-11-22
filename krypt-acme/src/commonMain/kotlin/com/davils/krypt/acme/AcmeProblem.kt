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
import kotlin.time.Duration

/**
 * A problem document of RFC 9457 the server answered with, read strictly: an object whose known members have their
 * types; unknown members are ignored.
 *
 * Every text comes from the server and may come from an attacker; [toString] escapes it. Values are immutable and
 * safe to share between threads.
 *
 * @property type the `type` URI, `about:blank` when the document has none.
 * @property kind the ACME error type of [type], or null if [type] names none.
 * @property title the short summary, or null.
 * @property detail the explanation for this occurrence, or null.
 * @property status the HTTP status the document names, or null.
 * @property instance the `instance` URI, such as the page of [AcmeProblemType.UserActionRequired], or null.
 * @property identifier the identifier a subproblem is about, or null.
 * @property subproblems the subproblems of RFC 8555 section 6.7.1, without their own subproblems.
 * @property retryAfter how long the `Retry-After` field of the response asks to wait, or null.
 * @since 1.0.0
 */
public class AcmeProblem internal constructor(
    public val type: String,
    public val kind: AcmeProblemType?,
    public val title: String?,
    public val detail: String?,
    public val status: Int?,
    public val instance: String?,
    public val identifier: AcmeIdentifier?,
    public val subproblems: List<AcmeProblem>,
    public val retryAfter: Duration?,
) : AcmeFailure {
    private val values: List<Any?>
        get() = listOf(type, title, detail, status, instance, identifier, subproblems, retryAfter)

    /**
     * Compares every member.
     *
     * @param other the other object.
     * @return true if [other] is the same problem.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is AcmeProblem && values == other.values

    /**
     * Hashes every member.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows the type and the detail, escaped.
     *
     * @return the problem as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "AcmeProblem(${SafeText.text(type)}, ${SafeText.text(detail ?: "no detail")}, ${subproblems.size} subproblems)"
}
