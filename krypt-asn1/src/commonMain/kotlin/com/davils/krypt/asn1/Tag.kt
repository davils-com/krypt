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

private const val CLASS_SHIFT: Int = 6
private const val CONSTRUCTED_BIT: Int = 0x20
private const val UNIVERSAL_BOOLEAN: Int = 1
private const val UNIVERSAL_INTEGER: Int = 2
private const val UNIVERSAL_BIT_STRING: Int = 3
private const val UNIVERSAL_OCTET_STRING: Int = 4
private const val UNIVERSAL_NULL: Int = 5
private const val UNIVERSAL_OBJECT_IDENTIFIER: Int = 6
private const val UNIVERSAL_ENUMERATED: Int = 10
private const val UNIVERSAL_UTF8_STRING: Int = 12
private const val UNIVERSAL_SEQUENCE: Int = 16
private const val UNIVERSAL_SET: Int = 17
private const val UNIVERSAL_NUMERIC_STRING: Int = 18
private const val UNIVERSAL_PRINTABLE_STRING: Int = 19
private const val UNIVERSAL_TELETEX_STRING: Int = 20
private const val UNIVERSAL_IA5_STRING: Int = 22
private const val UNIVERSAL_UTC_TIME: Int = 23
private const val UNIVERSAL_GENERALIZED_TIME: Int = 24
private const val UNIVERSAL_VISIBLE_STRING: Int = 26
private const val UNIVERSAL_UNIVERSAL_STRING: Int = 28
private const val UNIVERSAL_BMP_STRING: Int = 30
private const val HASH_FACTOR: Int = 31

/**
 * An ASN.1 tag: its class, whether the element is constructed, and its number.
 *
 * @property tagClass the class.
 * @property isConstructed whether the content of the element is a series of elements.
 * @property number the tag number, from 0 to [MAXIMUM_NUMBER].
 * @since 1.0.0
 */
public class Tag(public val tagClass: TagClass, public val isConstructed: Boolean, public val number: Int) {
    init {
        require(number in 0..MAXIMUM_NUMBER) { "A tag number lies between 0 and $MAXIMUM_NUMBER, not $number" }
    }

    internal val leadingOctet: Int
        get() = (tagClass.bits shl CLASS_SHIFT) or CONSTRUCTED_BIT * isConstructed.compareTo(false)

    /**
     * Compares class, construction and number.
     *
     * @param other the other object.
     * @return true if [other] is the same tag.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is Tag && tagClass == other.tagClass && isConstructed == other.isConstructed && number == other.number

    /**
     * Hashes class, construction and number.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = (tagClass.ordinal * HASH_FACTOR + isConstructed.hashCode()) * HASH_FACTOR + number

    /**
     * Shows the tag in the notation of X.680, such as `[0] constructed` or `UNIVERSAL 16 constructed`.
     *
     * @return the tag as text.
     * @since 1.0.0
     */
    override fun toString(): String {
        val form = listOf("primitive", "constructed")[isConstructed.compareTo(false)]
        return "$tagClass $number $form"
    }

    /**
     * The universal tags krypt reads and writes, and the factory of context-specific tags.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The largest tag number krypt reads: 2^21 - 1.
         *
         * @since 1.0.0
         */
        public const val MAXIMUM_NUMBER: Int = (1 shl 21) - 1

        /**
         * BOOLEAN.
         *
         * @since 1.0.0
         */
        public val Boolean: Tag = universal(UNIVERSAL_BOOLEAN)

        /**
         * INTEGER.
         *
         * @since 1.0.0
         */
        public val Integer: Tag = universal(UNIVERSAL_INTEGER)

        /**
         * BIT STRING.
         *
         * @since 1.0.0
         */
        public val BitString: Tag = universal(UNIVERSAL_BIT_STRING)

        /**
         * OCTET STRING.
         *
         * @since 1.0.0
         */
        public val OctetString: Tag = universal(UNIVERSAL_OCTET_STRING)

        /**
         * NULL.
         *
         * @since 1.0.0
         */
        public val Null: Tag = universal(UNIVERSAL_NULL)

        /**
         * OBJECT IDENTIFIER.
         *
         * @since 1.0.0
         */
        public val ObjectIdentifier: Tag = universal(UNIVERSAL_OBJECT_IDENTIFIER)

        /**
         * ENUMERATED.
         *
         * @since 1.0.0
         */
        public val Enumerated: Tag = universal(UNIVERSAL_ENUMERATED)

        /**
         * UTF8String.
         *
         * @since 1.0.0
         */
        public val Utf8String: Tag = universal(UNIVERSAL_UTF8_STRING)

        /**
         * SEQUENCE and SEQUENCE OF.
         *
         * @since 1.0.0
         */
        public val Sequence: Tag = Tag(TagClass.Universal, isConstructed = true, number = UNIVERSAL_SEQUENCE)

        /**
         * SET and SET OF.
         *
         * @since 1.0.0
         */
        public val Set: Tag = Tag(TagClass.Universal, isConstructed = true, number = UNIVERSAL_SET)

        /**
         * NumericString.
         *
         * @since 1.0.0
         */
        public val NumericString: Tag = universal(UNIVERSAL_NUMERIC_STRING)

        /**
         * PrintableString.
         *
         * @since 1.0.0
         */
        public val PrintableString: Tag = universal(UNIVERSAL_PRINTABLE_STRING)

        /**
         * TeletexString, read as Latin-1 the way every widespread implementation does.
         *
         * @since 1.0.0
         */
        public val TeletexString: Tag = universal(UNIVERSAL_TELETEX_STRING)

        /**
         * IA5String.
         *
         * @since 1.0.0
         */
        public val Ia5String: Tag = universal(UNIVERSAL_IA5_STRING)

        /**
         * UTCTime.
         *
         * @since 1.0.0
         */
        public val UtcTime: Tag = universal(UNIVERSAL_UTC_TIME)

        /**
         * GeneralizedTime.
         *
         * @since 1.0.0
         */
        public val GeneralizedTime: Tag = universal(UNIVERSAL_GENERALIZED_TIME)

        /**
         * VisibleString.
         *
         * @since 1.0.0
         */
        public val VisibleString: Tag = universal(UNIVERSAL_VISIBLE_STRING)

        /**
         * UniversalString, UTF-32 big endian.
         *
         * @since 1.0.0
         */
        public val UniversalString: Tag = universal(UNIVERSAL_UNIVERSAL_STRING)

        /**
         * BMPString, UTF-16 big endian.
         *
         * @since 1.0.0
         */
        public val BmpString: Tag = universal(UNIVERSAL_BMP_STRING)

        /**
         * Returns the context-specific tag `[number]`.
         *
         * @param number the tag number.
         * @param isConstructed whether the element is constructed, as an explicit tag always is.
         * @return the tag.
         * @throws IllegalArgumentException if [number] lies outside 0 to [MAXIMUM_NUMBER].
         * @since 1.0.0
         */
        public fun context(number: Int, isConstructed: Boolean): Tag =
            Tag(tagClass = TagClass.ContextSpecific, isConstructed = isConstructed, number = number)

        private fun universal(number: Int): Tag = Tag(TagClass.Universal, isConstructed = false, number = number)
    }
}
