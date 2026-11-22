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

package com.davils.krypt.cose

import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborTag
import kotlinx.io.bytestring.ByteString

/**
 * A COSE message of RFC 9052: signed, MACed or encrypted content with its two buckets of header parameters.
 *
 * Messages are immutable and safe to share between threads. A decoded message keeps the protected header parameters
 * as the bytes that arrived, because signatures, MACs and the additional data of encryption cover those bytes.
 *
 * @since 1.0.0
 */
public sealed class CoseMessage {
    /**
     * The type of the message.
     *
     * @since 1.0.0
     */
    public abstract val type: CoseMessageType

    /**
     * The protected header parameters.
     *
     * @since 1.0.0
     */
    public abstract val protectedHeaders: CoseHeaders

    /**
     * The serialized protected header parameters as they are covered: empty for an empty bucket, also when it
     * arrived as an encoded empty map, as RFC 9052 section 4.4 demands.
     *
     * @since 1.0.0
     */
    public abstract val protectedEncoding: ByteString

    /**
     * The unprotected header parameters.
     *
     * @since 1.0.0
     */
    public abstract val unprotectedHeaders: CoseHeaders

    internal abstract fun body(): List<CborItem>

    /**
     * Encodes the message.
     *
     * @param isTagged whether the CBOR tag of the [type] is written; true by default.
     * @return the encoding.
     * @since 1.0.0
     */
    public fun encode(isTagged: Boolean = true): ByteString {
        val array = CborArray(body())
        val tagged = CborTag(number = type.tag, content = array).takeIf { isTagged }
        return Cbor.encode(tagged ?: array)
    }
}
