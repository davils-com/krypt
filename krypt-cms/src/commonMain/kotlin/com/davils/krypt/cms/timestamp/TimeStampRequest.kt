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

package com.davils.krypt.cms.timestamp

import com.davils.krypt.asn1.DerInteger
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.core.algorithm.DigestAlgorithm
import kotlinx.io.bytestring.ByteString

/**
 * A TimeStampReq of RFC 3161.
 *
 * @property digest the digest of the message imprint, or null if krypt does not know it.
 * @property hashedMessage the digest of the message.
 * @property policy the policy the requester asks for, or null for the authority's default.
 * @property nonce the nonce, or null for none.
 * @property isCertificateRequested true if the token must carry the authority's certificate.
 * @property hasExtensions true if the request carries extensions, which krypt does not support.
 * @property encoded the DER encoding.
 * @since 1.0.0
 */
public class TimeStampRequest internal constructor(
    public val digest: DigestAlgorithm?,
    public val hashedMessage: ByteString,
    public val policy: ObjectIdentifier?,
    public val nonce: DerInteger?,
    public val isCertificateRequested: Boolean,
    public val hasExtensions: Boolean,
    public val encoded: ByteString,
) {
    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] has the same encoding.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is TimeStampRequest && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the digest and the options.
     *
     * @return the request as text.
     * @since 1.0.0
     */
    override fun toString(): String = "TimeStampRequest(${digest?.algorithmName.orEmpty()}, " +
        "policy=${policy?.dotted.orEmpty()}, nonce=${nonce != null}, certificate=$isCertificateRequested)"
}
