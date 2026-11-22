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

import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

/**
 * The signed content of a successful OCSP response.
 *
 * @property responderId how the responder names itself.
 * @property producedAt when the response was signed.
 * @property responses the answers, one per certificate.
 * @property nonce the nonce the responder echoed, or null.
 * @property signatureAlgorithm the algorithm of the signature, or null if krypt does not know it.
 * @property signature the signature.
 * @property certificates the certificates the responder sent, such as its own delegated certificate.
 * @property tbs the DER encoding of the signed part.
 * @since 1.0.0
 */
public class BasicOcspResponse internal constructor(
    public val responderId: ResponderId,
    public val producedAt: Instant,
    public val responses: List<SingleResponse>,
    public val nonce: ByteString?,
    public val signatureAlgorithm: SignatureAlgorithm?,
    public val signature: ByteString,
    public val certificates: List<Certificate>,
    public val tbs: ByteString,
) {
    /**
     * Compares the signed part and the signature.
     *
     * @param other the other object.
     * @return true if [other] is the same response.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is BasicOcspResponse && tbs == other.tbs && signature == other.signature

    /**
     * Hashes the signed part.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = tbs.hashCode()

    /**
     * Shows the responder, the time and the number of answers.
     *
     * @return the response as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "BasicOcspResponse($responderId, producedAt=$producedAt, responses=${responses.size})"
}
