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

package com.davils.krypt.asn1.pem

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import kotlinx.io.bytestring.ByteString

/**
 * One block of a PEM text of RFC 7468: its label, the headers of RFC 1421 if any, and the decoded bytes.
 *
 * Headers appear only in the legacy encrypted keys of OpenSSL, such as `Proc-Type: 4,ENCRYPTED`; krypt reports them
 * so that a caller can refuse such a key instead of misreading it.
 *
 * @property label the label, such as `CERTIFICATE`.
 * @property bytes the decoded bytes.
 * @property headers the RFC 1421 headers in their order, empty for an RFC 7468 block.
 * @since 1.0.0
 */
public class PemBlock(
    public val label: String,
    public val bytes: ByteString,
    public val headers: List<Pair<String, String>> = emptyList(),
) {
    /**
     * Compares label, bytes and headers.
     *
     * @param other the other object.
     * @return true if [other] is the same block.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is PemBlock && label == other.label && bytes == other.bytes && headers == other.headers

    /**
     * Hashes label, bytes and headers.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(label, bytes, headers).hashCode()

    /**
     * Shows the label and the size, never the bytes, which may be a private key.
     *
     * @return the block as text.
     * @since 1.0.0
     */
    override fun toString(): String = "PemBlock(${SafeText.text(label)}, size=${bytes.size}, headers=${headers.size})"
}
