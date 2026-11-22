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
import com.davils.krypt.asn1.internal.ReadContext
import com.davils.krypt.core.io.BufferSink
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val HIGH_TAG: Int = 0x1F
private const val SEVEN_BITS: Int = 7
private const val LOW_SEVEN: Int = 0x7F
private const val CONTINUATION: Int = 0x80
private const val BYTE_BITS: Int = 8
private const val SHORT_LENGTH_LIMIT: Int = 0x80
private const val LONG_FORM: Int = 0x80
private const val TRUE_OCTET: Int = 0xFF
private const val BYTE_MASK: Int = 0xFF

/**
 * Writes DER, one element after the other; see [Der.encode].
 *
 * Every value is written in its one DER form: minimal lengths and integers, BOOLEAN as 0x00 or 0xFF, the elements of
 * a SET OF sorted by their encoding, and times in the forms RFC 5280 prescribes. A writer is not thread safe.
 *
 * @since 1.0.0
 */
public class DerWriter internal constructor() {
    private val sink = BufferSink(DerLimits.HARD_MAXIMUM_BYTES)

    /**
     * Writes an element with [tag] and [content].
     *
     * @param tag the tag.
     * @param content the content octets.
     * @since 1.0.0
     */
    public fun element(tag: Tag, content: ByteString) {
        writeTag(tag)
        writeLength(content.size)
        sink.append(content.toByteArray())
    }

    /**
     * Writes a complete, already encoded element, such as the to-be-signed part of a certificate that is embedded
     * unchanged.
     *
     * @param encoded the encoding of exactly one element.
     * @throws IllegalArgumentException if [encoded] is not exactly one well-formed element.
     * @since 1.0.0
     */
    public fun raw(encoded: ByteString) {
        val isSingle = Der.decode(encoded) { readElement() }.isSuccess
        require(isSingle) { "Raw DER must be exactly one well-formed element" }
        sink.append(encoded.toByteArray())
    }

    /**
     * Writes a constructed element with [tag] whose content [block] writes.
     *
     * @param tag the tag, which must be constructed.
     * @param block writes the content.
     * @throws IllegalArgumentException if [tag] is primitive.
     * @since 1.0.0
     */
    public fun constructed(tag: Tag, block: DerWriter.() -> Unit) {
        require(tag.isConstructed) { "A constructed element needs a constructed tag, not $tag" }
        val nested = DerWriter()
        nested.block()
        element(tag = tag, content = nested.toByteString())
    }

    /**
     * Writes a SEQUENCE whose content [block] writes.
     *
     * @param block writes the content.
     * @since 1.0.0
     */
    public fun sequence(block: DerWriter.() -> Unit) {
        constructed(Tag.Sequence, block)
    }

    /**
     * Writes a SET OF whose elements [block] writes; they are sorted by their encoding, as DER requires.
     *
     * @param block writes the elements.
     * @since 1.0.0
     */
    public fun setOf(block: DerWriter.() -> Unit) {
        val nested = DerWriter()
        nested.block()
        val content = nested.toByteString().toByteArray()
        val reader = DerReader(
            input = content,
            start = 0,
            end = content.size,
            depth = 0,
            context = ReadContext(DerLimits.Default),
        )
        val encodings = reader.readRemaining().map { element -> element.encoded }
        val sorted = encodings.sortedWith(ENCODING_ORDER)
        val sortedContent = BufferSink(DerLimits.HARD_MAXIMUM_BYTES)
        sorted.forEach { encoded -> sortedContent.append(encoded.toByteArray()) }
        element(tag = Tag.Set, content = sortedContent.toByteString())
    }

    /**
     * Writes the explicitly tagged element `[number]` whose content [block] writes.
     *
     * @param number the context-specific tag number.
     * @param block writes the content.
     * @since 1.0.0
     */
    public fun explicit(number: Int, block: DerWriter.() -> Unit) {
        constructed(Tag.context(number = number, isConstructed = true), block)
    }

    /**
     * Writes an INTEGER.
     *
     * @param value the value.
     * @param tag the tag, [Tag.Integer] unless the INTEGER is implicitly tagged.
     * @since 1.0.0
     */
    public fun integer(value: Long, tag: Tag = Tag.Integer) {
        integer(value = DerInteger.of(value), tag = tag)
    }

    /**
     * Writes an INTEGER.
     *
     * @param value the value.
     * @param tag the tag, [Tag.Integer] unless the INTEGER is implicitly tagged.
     * @since 1.0.0
     */
    public fun integer(value: DerInteger, tag: Tag = Tag.Integer) {
        element(tag = tag, content = value.bytes)
    }

    /**
     * Writes a BOOLEAN.
     *
     * @param value the value.
     * @param tag the tag, [Tag.Boolean] unless the BOOLEAN is implicitly tagged.
     * @since 1.0.0
     */
    public fun boolean(value: Boolean, tag: Tag = Tag.Boolean) {
        element(tag = tag, content = ByteString((TRUE_OCTET * value.compareTo(false)).toByte()))
    }

    /**
     * Writes a NULL.
     *
     * @param tag the tag, [Tag.Null] unless the NULL is implicitly tagged.
     * @since 1.0.0
     */
    public fun nullValue(tag: Tag = Tag.Null) {
        element(tag = tag, content = ByteString())
    }

    /**
     * Writes an OBJECT IDENTIFIER.
     *
     * @param value the identifier.
     * @param tag the tag, [Tag.ObjectIdentifier] unless the identifier is implicitly tagged.
     * @since 1.0.0
     */
    public fun objectIdentifier(value: ObjectIdentifier, tag: Tag = Tag.ObjectIdentifier) {
        element(tag = tag, content = value.content)
    }

    /**
     * Writes an OCTET STRING.
     *
     * @param value the octets.
     * @param tag the tag, [Tag.OctetString] unless the string is implicitly tagged.
     * @since 1.0.0
     */
    public fun octetString(value: ByteString, tag: Tag = Tag.OctetString) {
        element(tag = tag, content = value)
    }

    /**
     * Writes an OCTET STRING whose content is the DER [block] writes, as an extension value is.
     *
     * @param block writes the encapsulated structure.
     * @since 1.0.0
     */
    public fun octetStringOf(block: DerWriter.() -> Unit) {
        octetString(Der.encode(block))
    }

    /**
     * Writes a BIT STRING.
     *
     * @param value the bits.
     * @param tag the tag, [Tag.BitString] unless the string is implicitly tagged.
     * @since 1.0.0
     */
    public fun bitString(value: BitString, tag: Tag = Tag.BitString) {
        val content = ByteArray(value.bytes.size + 1)
        content[0] = value.unusedBits.toByte()
        value.bytes.copyInto(destination = content, destinationOffset = 1)
        element(tag = tag, content = ByteString(content))
    }

    /**
     * Writes a UTF8String.
     *
     * @param value the text.
     * @param tag the tag, [Tag.Utf8String] unless the string is implicitly tagged.
     * @since 1.0.0
     */
    public fun utf8String(value: String, tag: Tag = Tag.Utf8String) {
        element(tag = tag, content = ByteString(value.encodeToByteArray()))
    }

    /**
     * Writes a PrintableString.
     *
     * @param value the text, of the characters PrintableString permits.
     * @param tag the tag, [Tag.PrintableString] unless the string is implicitly tagged.
     * @throws IllegalArgumentException if [value] holds a character PrintableString forbids.
     * @since 1.0.0
     */
    public fun printableString(value: String, tag: Tag = Tag.PrintableString) {
        require(
            value.all { char -> DerStrings.isPrintable(char) },
        ) { "The text holds a character PrintableString forbids" }
        element(tag = tag, content = ByteString(value.encodeToByteArray()))
    }

    /**
     * Writes an IA5String.
     *
     * @param value the text, ASCII only.
     * @param tag the tag, [Tag.Ia5String] unless the string is implicitly tagged, as in a DNS name.
     * @throws IllegalArgumentException if [value] holds a character outside ASCII.
     * @since 1.0.0
     */
    public fun ia5String(value: String, tag: Tag = Tag.Ia5String) {
        require(DerStrings.isAscii(value)) { "An IA5String holds ASCII only" }
        element(tag = tag, content = ByteString(value.encodeToByteArray()))
    }

    /**
     * Writes a time in the form RFC 5280 prescribes: a UTCTime for the years 1950 to 2049, a GeneralizedTime
     * otherwise, both in whole seconds.
     *
     * @param value the instant; fractions of a second are dropped.
     * @since 1.0.0
     */
    public fun time(value: Instant) {
        val whole = Instant.fromEpochSeconds(value.epochSeconds)
        val isUtc = DerTimes.isUtcTimeYear(whole)
        val tag = listOf(Tag.GeneralizedTime, Tag.UtcTime)[isUtc.compareTo(false)]
        val text = listOf(DerTimes.generalizedTime(whole), DerTimes.utcTime(whole))[isUtc.compareTo(false)]
        element(tag = tag, content = ByteString(text.encodeToByteArray()))
    }

    /**
     * Writes a GeneralizedTime, with a fraction of a second when [value] has one.
     *
     * @param value the instant, in the years 0 to 9999.
     * @param tag the tag, [Tag.GeneralizedTime] unless the time is implicitly tagged.
     * @throws IllegalArgumentException if [value] lies outside the years 0 to 9999.
     * @since 1.0.0
     */
    public fun generalizedTime(value: Instant, tag: Tag = Tag.GeneralizedTime) {
        element(tag = tag, content = ByteString(DerTimes.generalizedTime(value).encodeToByteArray()))
    }

    internal fun toByteString(): ByteString = sink.toByteString()

    private fun writeTag(tag: Tag) {
        val lead = tag.leadingOctet
        if (tag.number < HIGH_TAG) {
            sink.append(byteArrayOf((lead or tag.number).toByte()))
            return
        }
        val groups = mutableListOf((tag.number and LOW_SEVEN).toByte())
        var rest = tag.number ushr SEVEN_BITS
        while (rest > 0) {
            groups += ((rest and LOW_SEVEN) or CONTINUATION).toByte()
            rest = rest ushr SEVEN_BITS
        }
        sink.append(byteArrayOf((lead or HIGH_TAG).toByte()) + groups.asReversed().toByteArray())
    }

    private fun writeLength(length: Int) {
        if (length < SHORT_LENGTH_LIMIT) {
            sink.append(byteArrayOf(length.toByte()))
            return
        }
        val octets = (Int.SIZE_BYTES - 1 downTo 0)
            .map { index -> (length shr index * BYTE_BITS).toByte() }
            .dropWhile { octet -> octet.toInt() == 0 }
        sink.append(byteArrayOf((LONG_FORM or octets.size).toByte()) + octets.toByteArray())
    }

    private companion object {
        val ENCODING_ORDER: Comparator<ByteString> = Comparator { first, second ->
            val shared = minOf(a = first.size, b = second.size)
            val index = (0 until shared).firstOrNull { position -> first[position] != second[position] }
            val byByte = index?.let { position ->
                (first[position].toInt() and BYTE_MASK) -
                    (second[position].toInt() and BYTE_MASK)
            }
            byByte ?: first.size.compareTo(second.size)
        }
    }
}
