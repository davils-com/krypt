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

package com.davils.krypt.cms

/**
 * The limits of reading and writing CMS messages and time stamps, checked before any work.
 *
 * @property maximumBytes the size of one encoded message.
 * @property maximumContentBytes the size of the content that is signed, encrypted or decrypted.
 * @property maximumSigners how many signers one signed message carries, and how many countersignatures one signer.
 * @property maximumAttributes how many attributes one attribute set carries, and how many values one attribute.
 * @property maximumCertificates how many certificates one message carries.
 * @property maximumRevocationLists how many revocation lists one message carries.
 * @property maximumRecipients how many recipients one enveloped message names.
 * @property maximumNesting how deep countersignatures nest within countersignatures.
 * @constructor Checks the limits against their hard ceilings.
 * @throws IllegalArgumentException if a limit is not positive or exceeds its hard ceiling.
 * @since 1.0.0
 */
public class CmsLimits(
    public val maximumBytes: Int = DEFAULT_MAXIMUM_BYTES,
    public val maximumContentBytes: Int = DEFAULT_MAXIMUM_CONTENT_BYTES,
    public val maximumSigners: Int = DEFAULT_MAXIMUM_SIGNERS,
    public val maximumAttributes: Int = DEFAULT_MAXIMUM_ATTRIBUTES,
    public val maximumCertificates: Int = DEFAULT_MAXIMUM_CERTIFICATES,
    public val maximumRevocationLists: Int = DEFAULT_MAXIMUM_REVOCATION_LISTS,
    public val maximumRecipients: Int = DEFAULT_MAXIMUM_RECIPIENTS,
    public val maximumNesting: Int = DEFAULT_MAXIMUM_NESTING,
) {
    private val values: List<Int>
        get() = listOf(
            maximumBytes,
            maximumContentBytes,
            maximumSigners,
            maximumAttributes,
            maximumCertificates,
            maximumRevocationLists,
            maximumRecipients,
            maximumNesting,
        )

    init {
        require(maximumBytes in 1..HARD_MAXIMUM_BYTES) { "A CMS message has 1 to $HARD_MAXIMUM_BYTES bytes" }
        require(maximumContentBytes in 1..HARD_MAXIMUM_BYTES) { "A CMS content has 1 to $HARD_MAXIMUM_BYTES bytes" }
        require(maximumSigners in 1..HARD_MAXIMUM_SIGNERS) { "A message has 1 to $HARD_MAXIMUM_SIGNERS signers" }
        require(maximumAttributes in 1..HARD_MAXIMUM_ATTRIBUTES) {
            "An attribute set has 1 to $HARD_MAXIMUM_ATTRIBUTES attributes"
        }
        require(maximumCertificates in 1..HARD_MAXIMUM_CERTIFICATES) {
            "A message carries 1 to $HARD_MAXIMUM_CERTIFICATES certificates"
        }
        require(maximumRevocationLists in 1..HARD_MAXIMUM_REVOCATION_LISTS) {
            "A message carries 1 to $HARD_MAXIMUM_REVOCATION_LISTS revocation lists"
        }
        require(maximumRecipients in 1..HARD_MAXIMUM_RECIPIENTS) {
            "A message names 1 to $HARD_MAXIMUM_RECIPIENTS recipients"
        }
        require(maximumNesting in 1..HARD_MAXIMUM_NESTING) {
            "Countersignatures nest 1 to $HARD_MAXIMUM_NESTING levels deep"
        }
    }

    /**
     * Compares every limit.
     *
     * @param other the other object.
     * @return true if [other] has the same limits.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is CmsLimits && values == other.values

    /**
     * Hashes every limit.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = values.hashCode()

    /**
     * Shows every limit.
     *
     * @return the limits as text.
     * @since 1.0.0
     */
    override fun toString(): String = "CmsLimits(maximumBytes=$maximumBytes, " +
        "maximumContentBytes=$maximumContentBytes, maximumSigners=$maximumSigners, " +
        "maximumAttributes=$maximumAttributes, maximumCertificates=$maximumCertificates, " +
        "maximumRevocationLists=$maximumRevocationLists, maximumRecipients=$maximumRecipients, " +
        "maximumNesting=$maximumNesting)"

    /**
     * The defaults and the hard ceilings.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * The default size of a message: 16 MiB.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_BYTES: Int = 16_777_216

        /**
         * The default size of a content: 8 MiB.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_CONTENT_BYTES: Int = 8_388_608

        /**
         * The hard ceiling of the size of a message and of a content: 256 MiB.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_BYTES: Int = 268_435_456

        /**
         * The default number of signers.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_SIGNERS: Int = 8

        /**
         * The hard ceiling of the number of signers.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_SIGNERS: Int = 256

        /**
         * The default number of attributes in one set.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_ATTRIBUTES: Int = 32

        /**
         * The hard ceiling of the number of attributes in one set.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_ATTRIBUTES: Int = 1_024

        /**
         * The default number of certificates.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_CERTIFICATES: Int = 32

        /**
         * The hard ceiling of the number of certificates.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_CERTIFICATES: Int = 1_024

        /**
         * The default number of revocation lists.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_REVOCATION_LISTS: Int = 8

        /**
         * The hard ceiling of the number of revocation lists.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_REVOCATION_LISTS: Int = 256

        /**
         * The default number of recipients.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_RECIPIENTS: Int = 32

        /**
         * The hard ceiling of the number of recipients.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_RECIPIENTS: Int = 1_024

        /**
         * The default depth of nested countersignatures.
         *
         * @since 1.0.0
         */
        public const val DEFAULT_MAXIMUM_NESTING: Int = 2

        /**
         * The hard ceiling of the depth of nested countersignatures.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_NESTING: Int = 8

        /**
         * The default limits.
         *
         * @since 1.0.0
         */
        public val Default: CmsLimits = CmsLimits()
    }
}
