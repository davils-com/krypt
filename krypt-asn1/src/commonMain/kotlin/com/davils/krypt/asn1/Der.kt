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

package com.davils.krypt.asn1

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.asn1.internal.ReadContext
import kotlinx.io.bytestring.ByteString

/**
 * The entry points of DER: reading a structure from bytes and writing one.
 *
 * @since 1.0.0
 */
public object Der {
    /**
     * Reads [bytes] with [block], which must read every element.
     *
     * @param T what [block] reads.
     * @param bytes the DER input.
     * @param limits the bounds of the input; [DerLimits.Default] by default.
     * @param block reads the structure, throwing [DerException] for what it refuses.
     * @return what [block] returns, or why the input was refused.
     * @since 1.0.0
     */
    public fun <T> decode(
        bytes: ByteString,
        limits: DerLimits = DerLimits.Default,
        block: DerReader.() -> T,
    ): Outcome<T, DerFailure> {
        if (bytes.size > limits.maximumBytes) return Outcome.Failure(DerFailure.LimitExceeded)
        val array = bytes.toByteArray()
        val reader = DerReader(input = array, start = 0, end = array.size, depth = 0, context = ReadContext(limits))
        return try {
            val value = reader.block()
            reader.finish()
            Outcome.Success(value)
        } catch (refused: DerException) {
            Outcome.Failure(refused.failure)
        }
    }

    /**
     * Reads [bytes] with [block] like [decode], for a caller that needs no reason for a refusal.
     *
     * @param T what [block] reads.
     * @param bytes the DER input.
     * @param limits the bounds of the input; [DerLimits.Default] by default.
     * @param block reads the structure.
     * @return what [block] returns, or null if the input was refused.
     * @since 1.0.0
     */
    public fun <T> decodeOrNull(
        bytes: ByteString,
        limits: DerLimits = DerLimits.Default,
        block: DerReader.() -> T,
    ): T? {
        val outcome = decode(bytes = bytes, limits = limits, block = block)
        return (outcome as? Outcome.Success)?.value
    }

    /**
     * Writes the DER that [block] writes.
     *
     * @param block writes the elements.
     * @return the encoding.
     * @since 1.0.0
     */
    public fun encode(block: DerWriter.() -> Unit): ByteString {
        val writer = DerWriter()
        writer.block()
        return writer.toByteString()
    }
}
