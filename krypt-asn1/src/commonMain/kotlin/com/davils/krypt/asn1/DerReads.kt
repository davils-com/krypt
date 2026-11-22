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

package com.davils.krypt.asn1

import com.davils.krypt.asn1.internal.DerStrings
import com.davils.krypt.asn1.internal.DerTimes
import kotlin.time.Instant

/**
 * Reads an INTEGER that must lie within [range], such as a version number.
 *
 * @receiver the reader.
 * @param range the permitted values.
 * @param tag the tag, [Tag.Integer] unless the INTEGER is implicitly tagged.
 * @return the value.
 * @throws DerException if the element is missing or malformed or its value lies outside [range].
 * @since 1.0.0
 */
public fun DerReader.readInt(range: IntRange, tag: Tag = Tag.Integer): Int {
    val value = readInteger(tag).toLongOrNull()
    val inRange = value?.takeIf { long -> long in range.first.toLong()..range.last.toLong() }
    return inRange?.toInt() ?: throw DerException(DerFailure.InvalidValue, "an INTEGER in $range")
}

/**
 * Reads the elements of a SEQUENCE OF or a SET OF with [element], one call per element.
 *
 * @receiver the reader.
 * @param T the type of one element.
 * @param maximum the most elements the list may hold.
 * @param tag the tag of the list, [Tag.Sequence] by default or [Tag.Set] for a SET OF.
 * @param element reads one element.
 * @return the elements.
 * @throws DerException if the list is missing or malformed or holds more than [maximum] elements.
 * @since 1.0.0
 */
public fun <T> DerReader.readListOf(maximum: Int, tag: Tag = Tag.Sequence, element: DerReader.() -> T): List<T> =
    readConstructed(tag) {
        val items = mutableListOf<T>()
        while (!isExhausted) {
            if (items.size >= maximum) throw DerException(DerFailure.LimitExceeded, "at most $maximum list items")
            items += element()
        }
        items
    }

/**
 * Reads a string that must have [tag], such as an IA5String in a subject alternative name.
 *
 * @receiver the reader.
 * @param tag the tag, possibly an implicit context-specific tag of a string of type [type].
 * @param type the string type that decides the permitted characters; [tag] by default.
 * @return the text.
 * @throws DerException if the element is missing, has another tag or holds forbidden characters.
 * @since 1.0.0
 */
public fun DerReader.readText(tag: Tag, type: Tag = tag): String {
    val content = readElement(tag).content
    return DerStrings.decodeOrNull(type, content) ?: throw DerException(DerFailure.InvalidValue, "a valid $type")
}

/**
 * Reads a UTCTime or a GeneralizedTime, as the Time of RFC 5280 allows either.
 *
 * @receiver the reader.
 * @return the instant.
 * @throws DerException if the element is missing, is no time or is not in the one form DER allows.
 * @since 1.0.0
 */
public fun DerReader.readTime(): Instant {
    val element = readElement()
    val text = element.content.toByteArray().decodeToString()
    val utc = DerTimes.utcTimeOrNull(text).takeIf { element.tag == Tag.UtcTime }
    val generalized = DerTimes.generalizedTimeOrNull(text).takeIf { element.tag == Tag.GeneralizedTime }
    return utc ?: generalized ?: throw DerException(DerFailure.InvalidValue, "a UTCTime or GeneralizedTime")
}

/**
 * Reads a GeneralizedTime only, as OCSP and timestamps use.
 *
 * @receiver the reader.
 * @param tag the tag, [Tag.GeneralizedTime] unless the time is implicitly tagged.
 * @return the instant.
 * @throws DerException if the element is missing or not a canonical GeneralizedTime.
 * @since 1.0.0
 */
public fun DerReader.readGeneralizedTime(tag: Tag = Tag.GeneralizedTime): Instant {
    val content = readElement(tag).content
    val text = content.toByteArray().decodeToString()
    return DerTimes.generalizedTimeOrNull(text) ?: throw DerException(DerFailure.InvalidValue, "a GeneralizedTime")
}

/**
 * Reads the elements that remain.
 *
 * @receiver the reader.
 * @return the elements.
 * @throws DerException if one of them is malformed.
 * @since 1.0.0
 */
public fun DerReader.readRemaining(): List<DerElement> {
    val elements = mutableListOf<DerElement>()
    while (!isExhausted) elements += readElement()
    return elements
}
