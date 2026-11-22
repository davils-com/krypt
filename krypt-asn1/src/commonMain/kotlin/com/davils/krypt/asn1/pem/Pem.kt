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

package com.davils.krypt.asn1.pem

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.encoding.Base64
import kotlinx.io.bytestring.ByteString

private const val BEGIN: String = "-----BEGIN "
private const val END: String = "-----END "
private const val DASHES: String = "-----"
private const val LINE_LENGTH: Int = 64
private const val LABEL_FIRST: Int = 0x21
private const val LABEL_LAST: Int = 0x7E
private const val HEADER_SEPARATOR: String = ":"

/**
 * PEM of RFC 7468: reading blocks out of a text and writing them.
 *
 * Reading follows the lax parser of RFC 7468 section 3: text before, between and after blocks is ignored, line breaks
 * and whitespace inside a body are skipped, and RFC 1421 headers before the body are reported. Everything else is
 * strict: the end label must equal the begin label, and the body must be canonical Base64.
 *
 * @since 1.0.0
 */
public object Pem {
    /**
     * The longest text the reader accepts: 64 MiB.
     *
     * @since 1.0.0
     */
    public const val MAXIMUM_TEXT_LENGTH: Int = 64 * 1_024 * 1_024

    /**
     * The most blocks one text may hold: 10,000, enough for every bundle of root certificates.
     *
     * @since 1.0.0
     */
    public const val MAXIMUM_BLOCKS: Int = 10_000

    /**
     * The most RFC 1421 headers one block may hold: 16.
     *
     * @since 1.0.0
     */
    public const val MAXIMUM_HEADERS: Int = 16

    /**
     * Reads every block of [text].
     *
     * @param text the text, at most [MAXIMUM_TEXT_LENGTH] characters.
     * @return the blocks in their order, empty if the text holds none, or why the text is not valid PEM.
     * @since 1.0.0
     */
    public fun decode(text: String): Outcome<List<PemBlock>, PemFailure> {
        if (text.length > MAXIMUM_TEXT_LENGTH) return Outcome.Failure(PemFailure.LimitExceeded)
        val lines = text.lines().map { line -> line.trimEnd() }
        val blocks = mutableListOf<PemBlock>()
        var index = 0
        var failure: PemFailure? = null
        while (index < lines.size && failure == null) {
            val label = beginLabel(lines[index])
            val end = label?.let { found -> endOf(lines = lines, from = index + 1, label = found) }
            val body = end?.let { at -> lines.subList(fromIndex = index + 1, toIndex = at) }
            val block = body?.let { found -> blockOf(label = label, body = found) }
            failure = failureOf(label = label, end = end, block = block, count = blocks.size)
            block?.getOrNull()?.let { decoded -> blocks += decoded }
            index = (end ?: index) + 1
        }
        return failure?.let { refused -> Outcome.Failure(refused) } ?: Outcome.Success(blocks.toList())
    }

    /**
     * Writes [bytes] as one block labelled [label], with lines of 64 characters.
     *
     * @param label the label, such as `CERTIFICATE`.
     * @param bytes the bytes.
     * @return the block, ending with a line break.
     * @throws IllegalArgumentException if [label] is not a valid RFC 7468 label.
     * @since 1.0.0
     */
    public fun encode(label: String, bytes: ByteString): String {
        require(isLabel(label)) { "This is not a valid PEM label" }
        val body = Base64.encode(bytes).chunked(LINE_LENGTH)
        val lines = listOf("$BEGIN$label$DASHES") + body + "$END$label$DASHES"
        return lines.joinToString(separator = "\n", postfix = "\n")
    }

    /**
     * Writes every block, one after the other.
     *
     * @param blocks the blocks; their headers are not written.
     * @return the text.
     * @throws IllegalArgumentException if a label is not valid.
     * @since 1.0.0
     */
    public fun encode(blocks: List<PemBlock>): String =
        blocks.joinToString(separator = "") { block -> encode(label = block.label, bytes = block.bytes) }

    private fun failureOf(label: String?, end: Int?, block: Outcome<PemBlock, PemFailure>?, count: Int): PemFailure? {
        val unterminated = PemFailure.Unterminated.takeIf { label != null && end == null }
        val invalidLabel = PemFailure.InvalidLabel.takeIf { label != null && !isLabel(label) }
        val tooMany = PemFailure.LimitExceeded.takeIf { block != null && count >= MAXIMUM_BLOCKS }
        val malformed = (block as? Outcome.Failure)?.failure
        return invalidLabel ?: unterminated ?: tooMany ?: malformed
    }

    private fun endOf(lines: List<String>, from: Int, label: String): Int? {
        val rest = lines.subList(fromIndex = from, toIndex = lines.size)
        val offset = rest.indexOf("$END$label$DASHES")
        return offset.takeIf { found -> found >= 0 }?.let { found -> from + found }
    }

    private fun beginLabel(line: String): String? {
        val isBegin = line.startsWith(BEGIN) && line.endsWith(DASHES)
        val label = line.takeIf { isBegin }
        return label?.substring(startIndex = BEGIN.length, endIndex = line.length - DASHES.length)
    }

    private fun blockOf(label: String, body: List<String>): Outcome<PemBlock, PemFailure> {
        val headerLines = body.takeWhile { line -> line.contains(HEADER_SEPARATOR) }
        val separatorLines = blankAfter(body = body, index = headerLines.size) * headerLines.size.coerceAtMost(1)
        val contentLines = body.drop(headerLines.size + separatorLines)
        val headers = headerLines.map { line -> headerOf(line) }
        val base64 = contentLines.joinToString(
            separator = "",
        ) { line -> line.filterNot { char -> char.isWhitespace() } }
        val decoded = Base64.decode(base64).getOrNull()
        val tooMany = PemFailure.LimitExceeded.takeIf { headers.size > MAXIMUM_HEADERS }
        val failure = tooMany ?: PemFailure.InvalidBase64.takeIf { decoded == null }
        val block = PemBlock(label = label, bytes = decoded ?: ByteString(), headers = headers)
        return failure?.let { refused -> Outcome.Failure(refused) } ?: Outcome.Success(block)
    }

    private fun headerOf(line: String): Pair<String, String> {
        val name = line.substringBefore(HEADER_SEPARATOR)
        val value = line.substringAfter(HEADER_SEPARATOR)
        return name.trim() to value.trim()
    }

    private fun blankAfter(body: List<String>, index: Int): Int {
        val line = body.getOrNull(index) ?: return 0
        return line.isBlank().compareTo(false)
    }

    private fun isLabel(label: String): Boolean {
        val words = label.split(' ', '-')
        val hasSingleSeparators = words.all { word -> word.isNotEmpty() } || label.isEmpty()
        return hasSingleSeparators && label.all { char -> char.code in LABEL_FIRST..LABEL_LAST || char == ' ' }
    }
}
