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
import com.davils.krypt.cms.internal.concat
import kotlinx.io.bytestring.ByteString

internal fun innerParts(encoded: ByteString): List<ByteString> {
    val elements = Der.decodeOrNull(encoded) {
        readSequence {
            readObjectIdentifier()
            readExplicit(0) { readSequence { readRemaining() } }
        }
    }
    return checkNotNull(elements).map { element -> element.encoded }
}

internal fun contentInfo(type: ObjectIdentifier, parts: List<ByteString>): ByteString = der {
    sequence {
        objectIdentifier(type)
        explicit(0) { element(Tag.Sequence, concat(parts)) }
    }
}

internal fun sequenceOf(parts: List<ByteString>): ByteString = der { element(Tag.Sequence, concat(parts)) }

internal fun tagged(tag: Tag, parts: List<ByteString>): ByteString = der { element(tag, concat(parts)) }

internal fun constructed(number: Int): Tag = Tag.context(number = number, isConstructed = true)

internal fun List<ByteString>.with(index: Int, value: ByteString): List<ByteString> =
    mapIndexed { position, part -> value.takeIf { position == index } ?: part }
