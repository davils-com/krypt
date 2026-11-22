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

package com.davils.krypt.cose.internal

import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.cbor.Cbor
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborSimple
import com.davils.krypt.cose.cbor.CborText
import kotlinx.io.bytestring.ByteString

internal object Structures {
    const val SIGNATURE: String = "Signature"
    const val SIGNATURE1: String = "Signature1"
    const val MAC: String = "MAC"
    const val MAC0: String = "MAC0"
    const val ENCRYPT: String = "Encrypt"
    const val ENCRYPT0: String = "Encrypt0"
    private val PARTY_U: List<Long> =
        listOf(HeaderLabels.PARTY_U_IDENTITY, HeaderLabels.PARTY_U_NONCE, HeaderLabels.PARTY_U_OTHER)
    private val PARTY_V: List<Long> =
        listOf(HeaderLabels.PARTY_V_IDENTITY, HeaderLabels.PARTY_V_NONCE, HeaderLabels.PARTY_V_OTHER)

    fun signature(
        context: String,
        bodyProtected: ByteString,
        signerProtected: ByteString?,
        externalAad: ByteString,
        payload: ByteString,
    ): ByteString {
        val signer = signerProtected?.let { bytes -> listOf(CborBytes(bytes)) }.orEmpty()
        val head = listOf(CborText(context), CborBytes(bodyProtected))
        val tail = listOf(CborBytes(externalAad), CborBytes(payload))
        val items = head + signer + tail
        return Cbor.encode(CborArray(items))
    }

    fun mac(context: String, protectedEncoding: ByteString, externalAad: ByteString, payload: ByteString): ByteString =
        Cbor.encode(
            CborArray.of(CborText(context), CborBytes(protectedEncoding), CborBytes(externalAad), CborBytes(payload)),
        )

    fun encryption(context: String, protectedEncoding: ByteString, externalAad: ByteString): ByteString =
        Cbor.encode(CborArray.of(CborText(context), CborBytes(protectedEncoding), CborBytes(externalAad)))

    fun kdfContext(
        algorithmId: Long,
        keyBits: Int,
        protectedEncoding: ByteString,
        headers: List<CoseHeaders>,
    ): ByteString {
        val partyU = party(headers, PARTY_U)
        val partyV = party(headers, PARTY_V)
        val supplementary = CborArray.of(CborInteger.of(keyBits.toLong()), CborBytes(protectedEncoding))
        return Cbor.encode(CborArray.of(CborInteger.of(algorithmId), partyU, partyV, supplementary))
    }

    private fun party(headers: List<CoseHeaders>, labels: List<Long>): CborItem = CborArray(
        labels.map { label -> headers.firstNotNullOfOrNull { bucket -> bucket[label] } ?: CborSimple.Null },
    )
}
