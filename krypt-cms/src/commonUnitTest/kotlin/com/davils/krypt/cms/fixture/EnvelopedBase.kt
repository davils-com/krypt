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
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.readRemaining
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.enveloped.EnvelopedData
import kotlinx.io.bytestring.ByteString

private const val RECIPIENTS: Int = 1

internal class EnvelopedBase(val enveloped: EnvelopedData) {
    val parts: List<ByteString> = innerParts(enveloped.encoded)

    val recipient: List<ByteString> = childrenOf(enveloped.recipients.first().encoded)

    val type: ObjectIdentifier =
        listOf(ContentTypes.EnvelopedData, ContentTypes.AuthEnvelopedData)[enveloped.isAuthenticated.compareTo(false)]

    fun withRecipients(recipients: List<ByteString>): ByteString =
        contentInfo(type, parts.with(RECIPIENTS, tagged(Tag.Set, recipients)))

    fun withPart(index: Int, value: ByteString): ByteString = contentInfo(type, parts.with(index, value))

    fun withParts(parts: List<ByteString>): ByteString = contentInfo(type, parts)

    companion object {
        fun childrenOf(encoded: ByteString): List<ByteString> {
            val elements = Der.decodeOrNull(encoded) {
                val element = readElement()
                element.reader().readRemaining()
            }
            return checkNotNull(elements).map { element -> element.encoded }
        }
    }
}
