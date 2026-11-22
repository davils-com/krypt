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

package com.davils.krypt.cms.fixture

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.signed.SignedData
import com.davils.krypt.core.algorithm.KeyType
import kotlinx.io.bytestring.ByteString

private const val SIGNERS: Int = 4

internal class SignedBase(val pki: Pki, val identity: Identity, val signed: SignedData) {
    val parts: List<ByteString> = innerParts(signed.encoded)

    val signer: List<ByteString> = elementsOf(signed.signers.single().encoded)

    fun withSigner(fields: List<ByteString>): ByteString {
        val signers = tagged(com.davils.krypt.asn1.Tag.Set, listOf(sequenceOf(fields)))
        return contentInfo(ContentTypes.SignedData, parts.with(SIGNERS, signers))
    }

    fun withPart(index: Int, value: ByteString): ByteString = contentInfo(
        ContentTypes.SignedData,
        parts.with(index, value),
    )

    fun withExtra(value: ByteString): ByteString =
        contentInfo(ContentTypes.SignedData, parts.subList(fromIndex = 0, toIndex = SIGNERS) + value + parts[SIGNERS])

    companion object {
        suspend fun create(): SignedBase {
            val pki = Pki.create()
            val identity = pki.issue(KeyType.P256, "signer")
            val signed = cms.sign(CONTENT) { signer(identity.signer, identity.certificate) }
            return SignedBase(pki, identity, signed)
        }

        fun elementsOf(encoded: ByteString): List<ByteString> {
            val elements = Der.decodeOrNull(encoded) { readSequence { readRemaining() } }
            return checkNotNull(elements).map { element -> element.encoded }
        }
    }
}
