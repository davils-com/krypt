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

package com.davils.krypt.cms.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrElse
import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.DerException
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.Tag
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.buildByteString

private const val BYTE_MASK: Int = 0xFF

internal val ENCODING_ORDER: Comparator<ByteString> = Comparator { first, second ->
    val shared = minOf(a = first.size, b = second.size)
    val index = (0 until shared).firstOrNull { position -> first[position] != second[position] }
    val byByte = index?.let { position ->
        (first[position].toInt() and BYTE_MASK) - (second[position].toInt() and BYTE_MASK)
    }
    byByte ?: first.size.compareTo(second.size)
}

internal fun <T> successOf(outcome: Outcome<T, DerFailure>): T =
    outcome.getOrElse { failure -> throw DerException(failure, "an encoding krypt wrote itself") }

internal fun malformed(detail: String): Nothing = throw DerException(DerFailure.InvalidValue, detail)

internal fun limited(detail: String): Nothing = throw DerException(DerFailure.LimitExceeded, detail)

internal fun concat(parts: List<ByteString>): ByteString = buildByteString {
    parts.forEach { part -> append(part.toByteArray()) }
}

internal fun DerWriter.sortedSet(tag: Tag, encodings: List<ByteString>) {
    element(tag = tag, content = concat(encodings.sortedWith(ENCODING_ORDER)))
}

internal fun DerReader.readSetElements(tag: Tag, maximum: Int, isSorted: Boolean): List<DerElement> =
    setChildren(readElement(tag), maximum, isSorted)

internal fun setChildren(element: DerElement, maximum: Int, isSorted: Boolean): List<DerElement> {
    val reader = element.reader()
    val elements = mutableListOf<DerElement>()
    while (!reader.isExhausted) {
        if (elements.size >= maximum) limited("at most $maximum elements of a SET OF")
        val child = reader.readElement()
        val previous = elements.lastOrNull()?.encoded
        val isOrdered = !isSorted || previous == null || ENCODING_ORDER.compare(previous, child.encoded) <= 0
        if (!isOrdered) throw DerException(DerFailure.NonCanonicalValue, "a SET OF in DER order")
        elements += child
    }
    return elements
}

internal fun <T> DerElement.parse(expected: Tag, block: DerReader.() -> T): T {
    if (tag != expected) throw DerException(DerFailure.UnexpectedTag, "$expected, found $tag")
    val reader = reader()
    val result = reader.block()
    reader.finish()
    return result
}

internal fun DerReader.skipNullParameter() {
    if (isNext(Tag.Null)) readNull()
}

internal fun retagged(element: DerElement, tag: Tag): ByteString = Der.encode {
    element(tag = tag, content = element.content)
}
