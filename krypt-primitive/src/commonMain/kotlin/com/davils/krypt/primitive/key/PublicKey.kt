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

package com.davils.krypt.primitive.key

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.map
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.primitive.internal.KeyCodec
import com.davils.krypt.primitive.internal.KeyInfo
import kotlinx.io.bytestring.ByteString

/**
 * A public key, held as its SubjectPublicKeyInfo of RFC 5280: its family, its curve or size, and its encoding.
 *
 * A public key is only ever made by reading its encoding, so its family, curve and size are those of the encoding and
 * the policy checks the key that is used; there is no constructor a caller could hand other values. A public key is
 * immutable and thread safe. Two public keys are equal when their encodings are.
 *
 * @param info the family, the curve and the size the encoding holds.
 * @property encoded the DER encoding of the SubjectPublicKeyInfo.
 * @property raw the subjectPublicKey bits of the encoding, such as the point of an elliptic curve key.
 * @since 1.0.0
 */
public class PublicKey private constructor(
    info: KeyInfo,
    public val encoded: ByteString,
    internal val raw: ByteString,
) {
    /**
     * The family of the key.
     *
     * @since 1.0.0
     */
    public val family: KeyFamily = info.family

    /**
     * The curve of an elliptic curve key, or null.
     *
     * @since 1.0.0
     */
    public val curve: EllipticCurve? = info.curve

    /**
     * The size of the key: the modulus of RSA, the order of a curve, the security category of ML-DSA and ML-KEM.
     *
     * @since 1.0.0
     */
    public val bits: Int = info.bits

    internal var handle: Any? = null

    /**
     * Compares the encodings.
     *
     * @param other the other object.
     * @return true if [other] is the same public key.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is PublicKey && encoded == other.encoded

    /**
     * Hashes the encoding.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = encoded.hashCode()

    /**
     * Shows the family, the curve and the size.
     *
     * @return the key as text.
     * @since 1.0.0
     */
    override fun toString(): String = "PublicKey($family, curve=${curve?.curveName.orEmpty()}, bits=$bits)"

    internal companion object {
        fun decode(spki: ByteString): Outcome<PublicKey, KeyFailure> = KeyCodec.publicPartsOf(spki).map { parts ->
            PublicKey(info = parts.info, encoded = spki, raw = parts.raw)
        }
    }
}
