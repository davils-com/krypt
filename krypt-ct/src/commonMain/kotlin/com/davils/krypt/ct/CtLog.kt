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

package com.davils.krypt.ct

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.core.encoding.Hex
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * A Certificate Transparency log the application trusts, as a log list of a browser vendor names it.
 *
 * Create logs with [Transparency.log], which derives the id from the key.
 *
 * @property logId the id, the SHA-256 digest of the DER encoding of the public key.
 * @property publicKey the public key that signs the timestamps.
 * @property operator the organization that operates the log; timestamps count once per operator in a [CtPolicy].
 * @property usableFrom since when timestamps of the log count, or null for always.
 * @property usableUntil until when, exclusive, timestamps of the log count, such as when it was retired, or null.
 * @since 1.0.0
 */
@OptIn(DavilsInternal::class)
public class CtLog internal constructor(
    public val logId: ByteString,
    public val publicKey: PublicKey,
    public val operator: String,
    public val usableFrom: Instant?,
    public val usableUntil: Instant?,
) {
    /**
     * Tells whether a timestamp of [at] counts.
     *
     * @param at the time of the timestamp.
     * @return true if the log was usable at [at].
     * @since 1.0.0
     */
    public fun isUsableAt(at: Instant): Boolean {
        val hasStarted = usableFrom?.let { start -> at >= start } != false
        val hasNotEnded = usableUntil?.let { end -> at < end } != false
        return hasStarted && hasNotEnded
    }

    /**
     * Compares the id.
     *
     * @param other the other object.
     * @return true if [other] is the same log.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CtLog && logId == other.logId

    /**
     * Hashes the id.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = logId.hashCode()

    /**
     * Shows the id and the operator.
     *
     * @return the log as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CtLog(${Hex.encode(logId)}, operator=${SafeText.text(operator)})"
}
