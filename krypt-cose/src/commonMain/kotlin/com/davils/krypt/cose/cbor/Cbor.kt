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

package com.davils.krypt.cose.cbor

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.cose.internal.CborReader
import com.davils.krypt.cose.internal.CborWriter
import kotlinx.io.bytestring.ByteString

/**
 * The strict and bounded CBOR codec of RFC 8949.
 *
 * The writer produces the core deterministic encoding of section 4.2.1: preferred serialization with the shortest
 * arguments and floats, map keys sorted by the bytes of their encoding, and definite lengths only. The reader refuses
 * everything that is not well formed, every indefinite length, every duplicate map key, every text string that is not
 * valid UTF-8 and everything beyond its [CborLimits]; in [CborMode.Deterministic], the default, it also refuses every
 * encoding that is not deterministic. The codec holds no state and is safe to use from several threads.
 *
 * @since 1.0.0
 */
public object Cbor {
    /**
     * Encodes [item] deterministically.
     *
     * @param item the item.
     * @return the encoding.
     * @since 1.0.0
     */
    public fun encode(item: CborItem): ByteString = CborWriter.encode(item)

    /**
     * Decodes one data item that fills [encoded].
     *
     * @param encoded the encoding, possibly from an attacker.
     * @param limits the bounds of the input.
     * @param mode whether only the deterministic encoding is accepted.
     * @return the item, or why the encoding was refused.
     * @since 1.0.0
     */
    public fun decode(
        encoded: ByteString,
        limits: CborLimits = CborLimits.Default,
        mode: CborMode = CborMode.Deterministic,
    ): Outcome<CborItem, CborFailure> = CborReader.decode(encoded = encoded, limits = limits, mode = mode)
}
