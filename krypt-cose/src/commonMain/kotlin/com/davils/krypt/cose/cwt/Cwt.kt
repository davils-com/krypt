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

package com.davils.krypt.cose.cwt

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.cose.Cose
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseMessage
import com.davils.krypt.cose.CoseSigner
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborTag
import com.davils.krypt.cose.internal.CwtValidator
import com.davils.krypt.cose.key.CoseKey
import kotlinx.io.bytestring.ByteString

/**
 * Creates and validates CBOR Web Tokens by RFC 8392: claims signed as a COSE_Sign1, MACed as a COSE_Mac0 or encrypted
 * as a COSE_Encrypt0.
 *
 * A CWT is written with the tag of its COSE type and, if asked, the CWT tag 61 around it. Validation follows section
 * 7.2: an optional CWT tag, then the COSE tag or the [CwtValidation.untaggedType], the verification or decryption of
 * every layer with the algorithms of the validation, nested layers up to [MAXIMUM_LAYERS], and finally the claims and
 * their times against the clock of the environment. The object holds no key and is safe to share between threads.
 *
 * @property cose the COSE codec, its primitives, limits and mode.
 * @constructor Works with [cose].
 * @since 1.0.0
 */
public class Cwt(public val cose: Cose) {
    private val validator = CwtValidator(cose)

    /**
     * Signs [claims] as a COSE_Sign1.
     *
     * @param claims the claims.
     * @param signer the key, the algorithm and the header parameters.
     * @param isCwtTagged whether the CWT tag 61 is written around the COSE tag.
     * @return the encoded CWT.
     * @throws IllegalArgumentException if the headers of [signer] conflict.
     * @since 1.0.0
     */
    public suspend fun sign(claims: CwtClaims, signer: CoseSigner, isCwtTagged: Boolean = false): ByteString =
        encode(cose.sign1(payload = Cbor.encode(claims.claims), signer = signer), isCwtTagged)

    /**
     * MACs [claims] as a COSE_Mac0 with the symmetric [key].
     *
     * @param claims the claims.
     * @param key the MAC key.
     * @param algorithm the MAC algorithm.
     * @param isCwtTagged whether the CWT tag 61 is written around the COSE tag.
     * @return the encoded CWT.
     * @throws IllegalArgumentException if [key] does not fit [algorithm].
     * @since 1.0.0
     */
    public suspend fun mac(
        claims: CwtClaims,
        key: CoseKey,
        algorithm: CoseAlgorithm,
        isCwtTagged: Boolean = false,
    ): ByteString {
        val message = cose.mac0(payload = Cbor.encode(claims.claims), key = key, algorithm = algorithm)
        return encode(message, isCwtTagged)
    }

    /**
     * Encrypts [claims] as a COSE_Encrypt0 with the symmetric [key].
     *
     * @param claims the claims.
     * @param key the content key.
     * @param algorithm the content encryption algorithm.
     * @param isCwtTagged whether the CWT tag 61 is written around the COSE tag.
     * @return the encoded CWT.
     * @throws IllegalArgumentException if [key] does not fit [algorithm].
     * @since 1.0.0
     */
    public suspend fun encrypt(
        claims: CwtClaims,
        key: CoseKey,
        algorithm: CoseAlgorithm,
        isCwtTagged: Boolean = false,
    ): ByteString {
        val message = cose.encrypt0(plaintext = Cbor.encode(claims.claims), key = key, algorithm = algorithm)
        return encode(message, isCwtTagged)
    }

    /**
     * Validates the CWT [encoded] with one of [keys] for every layer.
     *
     * @param encoded the CWT, possibly from an attacker.
     * @param keys the keys to try in every layer.
     * @param validation the algorithms and the claims to check.
     * @return the claims, or why the CWT is refused.
     * @since 1.0.0
     */
    public suspend fun validate(
        encoded: ByteString,
        keys: List<CoseKey>,
        validation: CwtValidation,
    ): Outcome<CwtClaims, CwtFailure> = validator.validate(encoded = encoded, keys = keys, validation = validation)

    /**
     * Shows the COSE codec.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Cwt($cose)"

    private fun encode(message: CoseMessage, isCwtTagged: Boolean): ByteString {
        val tagged = CborTag(number = message.type.tag, content = CborArray(message.body()))
        val wrapped = CborTag(number = TAG, content = tagged).takeIf { isCwtTagged }
        return Cbor.encode(wrapped ?: tagged)
    }

    /**
     * The tag and the depth of CWTs.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The CBOR tag of a CWT.
         *
         * @since 1.0.0
         */
        public const val TAG: ULong = 61UL

        /**
         * The most COSE layers a CWT may nest, such as a signed CWT inside an encrypted one.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_LAYERS: Int = 3
    }
}
