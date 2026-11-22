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

import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.internal.HeaderLabels
import com.davils.krypt.cose.internal.HeaderRules
import com.davils.krypt.cose.internal.bytesAt
import com.davils.krypt.cose.internal.itemsAt
import com.davils.krypt.cose.internal.labelOf
import com.davils.krypt.cose.internal.longAt
import com.davils.krypt.cose.internal.sure
import com.davils.krypt.x509.Certificate
import kotlinx.io.bytestring.ByteString

/**
 * One bucket of header parameters of RFC 9052, protected or unprotected, with typed access to the common parameters
 * of RFC 9052 and RFC 9360.
 *
 * The parameters are checked on creation: every label is an integer or a text, and the common parameters have their
 * types (`alg` an integer or a text, `crit` a non-empty array of labels, `content type` an unsigned integer or a text,
 * `kid`, `IV` and `Partial IV` byte strings, never both IVs, `x5chain` a byte string or an array of them, `x5t` a
 * COSE_CertHash, and the parameters of key agreement theirs). Headers are immutable and safe to share between
 * threads.
 *
 * @property parameters every parameter of the bucket.
 * @since 1.0.0
 */
public class CoseHeaders private constructor(public val parameters: CborMap) {
    /**
     * The `alg` parameter if it names an algorithm krypt implements, or null if it is absent or unknown.
     *
     * @since 1.0.0
     */
    public val algorithm: CoseAlgorithm?
        get() = parameters.longAt(HeaderLabels.ALGORITHM)?.let { id -> CoseAlgorithm.of(id) }

    /**
     * The labels of the `crit` parameter, empty if it is absent.
     *
     * @since 1.0.0
     */
    public val critical: List<CborItem> get() = parameters.itemsAt(HeaderLabels.CRITICAL).orEmpty()

    /**
     * The `content type` parameter, an unsigned integer of CoAP or a media type as text, or null.
     *
     * @since 1.0.0
     */
    public val contentType: CborItem? get() = parameters[HeaderLabels.CONTENT_TYPE]

    /**
     * The `kid` parameter, or null.
     *
     * @since 1.0.0
     */
    public val keyId: ByteString? get() = parameters.bytesAt(HeaderLabels.KEY_ID)

    /**
     * The `IV` parameter, or null.
     *
     * @since 1.0.0
     */
    public val iv: ByteString? get() = parameters.bytesAt(HeaderLabels.IV)

    /**
     * The `Partial IV` parameter, or null.
     *
     * @since 1.0.0
     */
    public val partialIv: ByteString? get() = parameters.bytesAt(HeaderLabels.PARTIAL_IV)

    /**
     * The DER encodings of the `x5chain` parameter of RFC 9360, the end-entity certificate first; empty if it is
     * absent. [Cose.certificateChain] reads them as certificates.
     *
     * @since 1.0.0
     */
    public val certificateChain: List<ByteString>
        get() {
            val single = parameters.bytesAt(HeaderLabels.CERTIFICATE_CHAIN)?.let { bytes -> listOf(bytes) }
            val several = parameters.itemsAt(HeaderLabels.CERTIFICATE_CHAIN).orEmpty()
            return single ?: several.mapNotNull { item -> item.bytesOrNull() }
        }

    /**
     * The `x5t` parameter of RFC 9360, or null.
     *
     * @since 1.0.0
     */
    public val certificateHash: CoseCertificateHash?
        get() = parameters.itemsAt(HeaderLabels.CERTIFICATE_HASH)?.let { parts ->
            CoseCertificateHash(algorithm = parts[0], value = parts[1].bytesOrNull().sure())
        }

    /**
     * Tells whether the bucket has no parameter.
     *
     * @since 1.0.0
     */
    public val isEmpty: Boolean get() = parameters.size == 0

    /**
     * Returns the parameter with the integer label [label].
     *
     * @param label the label.
     * @return the value, or null if the bucket has no such parameter.
     * @since 1.0.0
     */
    public operator fun get(label: Long): CborItem? = parameters[label]

    /**
     * Returns the parameter with [label], an integer or a text.
     *
     * @param label the label.
     * @return the value, or null if the bucket has no such parameter.
     * @since 1.0.0
     */
    public operator fun get(label: CborItem): CborItem? = parameters[label]

    internal fun with(label: Long, value: CborItem): CoseHeaders {
        val key = labelOf(label)
        val kept = parameters.entries.filterNot { entry -> entry.first == key }
        return CoseHeaders(CborMap(kept + (key to value)))
    }

    /**
     * Compares the parameters.
     *
     * @param other the other object.
     * @return true if [other] has the same parameters.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CoseHeaders && parameters == other.parameters

    /**
     * Hashes the parameters.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = parameters.hashCode()

    /**
     * Shows the parameters in the diagnostic notation of CBOR, escaping their text.
     *
     * @return the headers as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CoseHeaders($parameters)"

    /**
     * The factories of headers.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The empty bucket.
         *
         * @since 1.0.0
         */
        public val Empty: CoseHeaders = CoseHeaders(CborMap.Empty)

        /**
         * Returns the bucket of [parameters].
         *
         * @param parameters the parameters.
         * @return the headers.
         * @throws IllegalArgumentException if a label is neither an integer nor a text, or a common parameter has the
         *   wrong type.
         * @since 1.0.0
         */
        public fun of(parameters: CborMap): CoseHeaders {
            require(HeaderRules.isValid(parameters)) { "The header parameters have labels and values of their types" }
            return CoseHeaders(parameters)
        }

        /**
         * Returns a bucket of the common parameters.
         *
         * @param keyId the `kid`, or null.
         * @param contentType the `content type`, an unsigned integer or a text, or null.
         * @param certificateChain the certificates of `x5chain`, the end-entity certificate first; none by default.
         * @param certificateHash the `x5t`, or null.
         * @param critical the labels of `crit`; none by default.
         * @param parameters further parameters, whose labels must differ from the ones above.
         * @return the headers.
         * @throws IllegalArgumentException if a parameter has the wrong type or a label is given twice.
         * @since 1.0.0
         */
        public fun of(
            keyId: ByteString? = null,
            contentType: CborItem? = null,
            certificateChain: List<Certificate> = emptyList(),
            certificateHash: CoseCertificateHash? = null,
            critical: List<CborItem> = emptyList(),
            parameters: CborMap = CborMap.Empty,
        ): CoseHeaders {
            val encodings = certificateChain.map { certificate -> CborBytes(certificate.encoded) }
            val chain = encodings.singleOrNull() ?: CborArray(encodings).takeIf { encodings.isNotEmpty() }
            val common = listOf(
                HeaderLabels.KEY_ID to keyId?.let { bytes -> CborBytes(bytes) },
                HeaderLabels.CONTENT_TYPE to contentType,
                HeaderLabels.CERTIFICATE_CHAIN to chain,
                HeaderLabels.CERTIFICATE_HASH to certificateHash?.toItem(),
                HeaderLabels.CRITICAL to CborArray(critical).takeIf { critical.isNotEmpty() },
            )
            val given = common.mapNotNull { (label, value) -> value?.let { found -> CborInteger.of(label) to found } }
            return of(CborMap(given + parameters.entries))
        }

        internal fun ofOrNull(parameters: CborMap): CoseHeaders? =
            CoseHeaders(parameters).takeIf { HeaderRules.isValid(parameters) }
    }
}
