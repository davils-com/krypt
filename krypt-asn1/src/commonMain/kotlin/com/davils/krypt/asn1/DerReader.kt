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
import com.davils.krypt.asn1.internal.ReadContext
import com.davils.krypt.asn1.internal.unsignedAtOrNull
import kotlinx.io.bytestring.ByteString

private const val CLASS_SHIFT: Int = 6
private const val CONSTRUCTED_BIT: Int = 0x20
private const val NUMBER_MASK: Int = 0x1F
private const val HIGH_TAG: Int = 0x1F
private const val SEVEN_BITS: Int = 7
private const val LOW_SEVEN: Int = 0x7F
private const val CONTINUATION: Int = 0x80
private const val BYTE_MASK: Int = 0xFF
private const val BYTE_BITS: Int = 8
private const val LONG_FORM: Int = 0x80
private const val MAXIMUM_LENGTH_BYTES: Int = 4
private const val TRUE_OCTET: Int = 0xFF
private const val MAXIMUM_UNUSED_BITS: Int = 7

/**
 * Reads the elements of a DER input one after the other, strictly: every element must be in the one encoding DER
 * allows, every element must fit inside its parent, and nothing may follow the last element.
 *
 * Every read function throws [DerException] on input it refuses; [Der.decode] catches it and returns a failed outcome.
 * A reader is not thread safe.
 *
 * @since 1.0.0
 */
public class DerReader internal constructor(
    private val input: ByteArray,
    start: Int,
    private val end: Int,
    private val depth: Int,
    private val context: ReadContext,
) {
    private var position = start

    /**
     * Tells whether every element was read.
     *
     * @since 1.0.0
     */
    public val isExhausted: Boolean get() = position >= end

    /**
     * Returns the tag of the next element without reading it, or null if the reader is exhausted.
     *
     * @return the tag or null.
     * @throws DerException if the identifier octets are malformed.
     * @since 1.0.0
     */
    public fun peekTag(): Tag? = position.takeIf { at -> at < end }?.let { at -> tagAt(at).first }

    /**
     * Tells whether the next element has [tag].
     *
     * @param tag the tag.
     * @return true if an element follows and has [tag].
     * @throws DerException if the identifier octets are malformed.
     * @since 1.0.0
     */
    public fun isNext(tag: Tag): Boolean = peekTag() == tag

    /**
     * Reads the next element, whatever its tag.
     *
     * @return the element.
     * @throws DerException if no element follows or it is malformed.
     * @since 1.0.0
     */
    public fun readElement(): DerElement {
        if (isExhausted) throw DerException(DerFailure.Truncated, "an element, found the end of the input")
        context.countElement()
        val (tag, afterTag) = tagAt(position)
        val (length, afterLength) = lengthAt(afterTag)
        if (length > end - afterLength) throw DerException(DerFailure.Truncated, "$length content octets of $tag")
        val element = DerElement(
            tag = tag,
            content = ByteString(data = input, startIndex = afterLength, endIndex = afterLength + length),
            encoded = ByteString(data = input, startIndex = position, endIndex = afterLength + length),
            depth = depth,
            context = context,
        )
        position = afterLength + length
        return element
    }

    /**
     * Reads the next element, which must have [expected] as its tag.
     *
     * @param expected the tag.
     * @return the element.
     * @throws DerException if no element follows, it is malformed or it has another tag.
     * @since 1.0.0
     */
    public fun readElement(expected: Tag): DerElement {
        val element = readElement()
        if (element.tag != expected) throw DerException(DerFailure.UnexpectedTag, "$expected, found ${element.tag}")
        return element
    }

    /**
     * Reads the next element if it has [expected] as its tag, as an OPTIONAL or DEFAULT component.
     *
     * @param expected the tag.
     * @return the element, or null if the reader is exhausted or the next element has another tag.
     * @throws DerException if the element is malformed.
     * @since 1.0.0
     */
    public fun readOptional(expected: Tag): DerElement? =
        expected.takeIf { tag -> isNext(tag) }?.let { tag -> readElement(tag) }

    /**
     * Reads a constructed element with [tag] and its whole content with [block].
     *
     * @param T the result of [block].
     * @param tag the tag of the constructed element.
     * @param block reads the content; it must read every element.
     * @return what [block] returns.
     * @throws DerException if the element is missing, malformed or not fully read.
     * @since 1.0.0
     */
    public fun <T> readConstructed(tag: Tag, block: DerReader.() -> T): T {
        val nested = readElement(tag).reader()
        val result = nested.block()
        nested.finish()
        return result
    }

    /**
     * Reads a SEQUENCE and its content with [block].
     *
     * @param T the result of [block].
     * @param block reads the content; it must read every element.
     * @return what [block] returns.
     * @throws DerException if the SEQUENCE is missing, malformed or not fully read.
     * @since 1.0.0
     */
    public fun <T> readSequence(block: DerReader.() -> T): T = readConstructed(Tag.Sequence, block)

    /**
     * Reads a SET OF and its content with [block], in the order the elements were encoded, which DER requires to be
     * ascending by their encodings (X.690 §11.6); equal elements may follow each other.
     *
     * @param T the result of [block].
     * @param block reads the content; it must read every element.
     * @return what [block] returns.
     * @throws DerException if the SET is missing, malformed, not sorted or not fully read.
     * @since 1.0.0
     */
    public fun <T> readSet(block: DerReader.() -> T): T = readConstructed(Tag.Set) {
        checkSorted()
        block()
    }

    /**
     * Reads the explicitly tagged element `[number]` and its content with [block].
     *
     * @param T the result of [block].
     * @param number the context-specific tag number.
     * @param block reads the content; it must read every element.
     * @return what [block] returns.
     * @throws DerException if the element is missing, malformed or not fully read.
     * @since 1.0.0
     */
    public fun <T> readExplicit(number: Int, block: DerReader.() -> T): T =
        readConstructed(Tag.context(number = number, isConstructed = true), block)

    /**
     * Reads the explicitly tagged element `[number]` with [block] if it is next.
     *
     * @param T the result of [block].
     * @param number the context-specific tag number.
     * @param block reads the content; it must read every element.
     * @return what [block] returns, or null if the element is absent.
     * @throws DerException if the element is malformed or not fully read.
     * @since 1.0.0
     */
    public fun <T> readOptionalExplicit(number: Int, block: DerReader.() -> T): T? {
        val tag = Tag.context(number = number, isConstructed = true)
        return tag.takeIf { candidate -> isNext(candidate) }?.let { present -> readConstructed(present, block) }
    }

    /**
     * Reads an INTEGER.
     *
     * @param tag the tag, [Tag.Integer] unless the INTEGER is implicitly tagged.
     * @return the integer.
     * @throws DerException if the element is missing, has another tag or is not a minimal INTEGER.
     * @since 1.0.0
     */
    public fun readInteger(tag: Tag = Tag.Integer): DerInteger {
        val content = readElement(tag).content
        return DerInteger.decodeOrNull(content) ?: throw DerException(DerFailure.NonCanonicalValue, "a minimal INTEGER")
    }

    /**
     * Reads a BOOLEAN, which DER encodes as 0x00 or 0xFF only.
     *
     * @param tag the tag, [Tag.Boolean] unless the BOOLEAN is implicitly tagged.
     * @return the value.
     * @throws DerException if the element is missing or not a canonical BOOLEAN.
     * @since 1.0.0
     */
    public fun readBoolean(tag: Tag = Tag.Boolean): Boolean {
        val content = readElement(tag).content
        val octet = content.unsignedAtOrNull(0).takeIf { content.size == 1 }
        if (octet != 0 && octet != TRUE_OCTET) throw DerException(DerFailure.NonCanonicalValue, "a BOOLEAN of 00 or FF")
        return octet == TRUE_OCTET
    }

    /**
     * Reads a NULL.
     *
     * @param tag the tag, [Tag.Null] unless the NULL is implicitly tagged.
     * @throws DerException if the element is missing or not empty.
     * @since 1.0.0
     */
    public fun readNull(tag: Tag = Tag.Null) {
        if (readElement(tag).content.size > 0) throw DerException(DerFailure.NonCanonicalValue, "an empty NULL")
    }

    /**
     * Reads an OBJECT IDENTIFIER.
     *
     * @param tag the tag, [Tag.ObjectIdentifier] unless the identifier is implicitly tagged.
     * @return the identifier.
     * @throws DerException if the element is missing or not a valid, minimal identifier.
     * @since 1.0.0
     */
    public fun readObjectIdentifier(tag: Tag = Tag.ObjectIdentifier): ObjectIdentifier {
        val content = readElement(tag).content
        return ObjectIdentifier.decodeOrNull(
            content,
        ) ?: throw DerException(DerFailure.InvalidValue, "an OBJECT IDENTIFIER")
    }

    /**
     * Reads an OCTET STRING.
     *
     * @param tag the tag, [Tag.OctetString] unless the string is implicitly tagged.
     * @return the octets.
     * @throws DerException if the element is missing or has another tag.
     * @since 1.0.0
     */
    public fun readOctetString(tag: Tag = Tag.OctetString): ByteString = readElement(tag).content

    /**
     * Reads a BIT STRING, whose unused bits DER requires to be zero.
     *
     * @param tag the tag, [Tag.BitString] unless the string is implicitly tagged.
     * @return the bits.
     * @throws DerException if the element is missing or not a canonical BIT STRING.
     * @since 1.0.0
     */
    public fun readBitString(tag: Tag = Tag.BitString): BitString {
        val content = readElement(tag).content
        val unused = content.unsignedAtOrNull(0) ?: -1
        val bits = ByteString(content.toByteArray(startIndex = minOf(a = 1, b = content.size)))
        val last = bits.unsignedAtOrNull(bits.size - 1) ?: 0
        val isCanonical = unused in 0..MAXIMUM_UNUSED_BITS &&
            (bits.size > 0 || unused == 0) &&
            last and (1 shl unused) - 1 == 0
        if (!isCanonical) throw DerException(DerFailure.NonCanonicalValue, "a BIT STRING with zero unused bits")
        return BitString(bytes = bits, unusedBits = unused)
    }

    /**
     * Reads a string of any ASN.1 string type, checking the characters its type permits.
     *
     * @return the text.
     * @throws DerException if the element is missing, is not a string or holds characters its type forbids.
     * @since 1.0.0
     */
    public fun readText(): String {
        val element = readElement()
        return DerStrings.decodeOrNull(element.tag, element.content)
            ?: throw DerException(DerFailure.InvalidValue, "a valid string, found ${element.tag}")
    }

    /**
     * Refuses the input with [failure], for a structure the caller finds invalid.
     *
     * @param failure why the input is refused.
     * @param detail what was expected.
     * @return never.
     * @throws DerException always.
     * @since 1.0.0
     */
    public fun refuse(failure: DerFailure, detail: String): Nothing = throw DerException(failure, detail)

    /**
     * Checks that every element was read.
     *
     * @throws DerException if elements remain.
     * @since 1.0.0
     */
    public fun finish() {
        if (!isExhausted) throw DerException(DerFailure.TrailingData, "the end of the structure")
    }

    internal fun checkSorted() {
        var previous = IntRange.EMPTY
        var at = position
        while (at < end) {
            val (_, afterTag) = tagAt(at)
            val (length, afterLength) = lengthAt(afterTag)
            ensure(isValid = length <= end - afterLength, failure = DerFailure.Truncated, detail = "a SET element")
            val current = at until afterLength + length
            ensure(
                isValid = previous.isEmpty() || !isAfter(input = input, first = previous, second = current),
                failure = DerFailure.NonCanonicalValue,
                detail = "a SET OF sorted by the encodings of its elements",
            )
            previous = current
            at = afterLength + length
        }
    }

    private fun tagAt(at: Int): Pair<Tag, Int> {
        val first = input[at].toInt() and BYTE_MASK
        val tagClass = TagClass.entries[first shr CLASS_SHIFT]
        val isConstructed = first and CONSTRUCTED_BIT != 0
        val low = first and NUMBER_MASK
        val high = (at + 1).takeIf { low == HIGH_TAG }?.let { from -> highTagAt(from) }
        val (number, next) = high ?: (low to at + 1)
        return Tag(tagClass = tagClass, isConstructed = isConstructed, number = number) to next
    }

    private fun highTagAt(at: Int): Pair<Int, Int> {
        var cursor = at
        var number = 0L
        var octet = CONTINUATION
        while (octet and CONTINUATION != 0) {
            ensure(isValid = cursor < end, failure = DerFailure.Truncated, detail = "the octets of a tag number")
            octet = input[cursor].toInt() and BYTE_MASK
            val isPadded = cursor == at && octet == CONTINUATION
            number = (number shl SEVEN_BITS) or (octet and LOW_SEVEN).toLong()
            val isMinimal = !isPadded && number <= Tag.MAXIMUM_NUMBER
            ensure(isValid = isMinimal, failure = DerFailure.NonMinimalEncoding, detail = "a minimal tag number")
            cursor += 1
        }
        ensure(isValid = number >= HIGH_TAG, failure = DerFailure.NonMinimalEncoding, detail = "a tag number above 30")
        return number.toInt() to cursor
    }

    private fun lengthAt(at: Int): Pair<Int, Int> {
        ensure(isValid = at < end, failure = DerFailure.Truncated, detail = "the length octets")
        val first = input[at].toInt() and BYTE_MASK
        val isLongForm = first and LONG_FORM != 0
        val count = (first and LOW_SEVEN) * isLongForm.compareTo(false)
        val isDefinite = !isLongForm || count in 1..MAXIMUM_LENGTH_BYTES
        ensure(isValid = isDefinite, failure = DerFailure.NonMinimalEncoding, detail = "a definite length")
        ensure(isValid = at + count < end, failure = DerFailure.Truncated, detail = "the length octets")
        val long = (1..count).fold(0L) { value, offset -> (value shl BYTE_BITS) or unsignedAt(at + offset) }
        val hasMinimalLead = long shr (count - 1) * BYTE_BITS != 0L
        val isMinimal = !isLongForm || (long >= LONG_FORM && hasMinimalLead)
        ensure(
            isValid = isMinimal && long <= Int.MAX_VALUE,
            failure = DerFailure.NonMinimalEncoding,
            detail = "a minimal length",
        )
        val length = listOf(first.toLong(), long)[isLongForm.compareTo(false)]
        return length.toInt() to at + 1 + count
    }

    private fun unsignedAt(index: Int): Long = input[index].toLong() and BYTE_MASK.toLong()

    private fun ensure(isValid: Boolean, failure: DerFailure, detail: String) {
        if (!isValid) throw DerException(failure, detail)
    }
}

private fun isAfter(input: ByteArray, first: IntRange, second: IntRange): Boolean {
    val firstSize = first.last - first.first + 1
    val secondSize = second.last - second.first + 1
    val shared = minOf(a = firstSize, b = secondSize)
    var index = 0
    while (index < shared && input[first.first + index] == input[second.first + index]) index += 1
    if (index == shared) return firstSize > secondSize
    val firstOctet = input[first.first + index].toInt() and BYTE_MASK
    val secondOctet = input[second.first + index].toInt() and BYTE_MASK
    return firstOctet > secondOctet
}
