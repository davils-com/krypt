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

package com.davils.krypt.x509.internal

import kotlinx.io.bytestring.ByteString

private const val IPV4: Int = 4
private const val IPV6: Int = 16
private const val GROUPS: Int = 8
private const val OCTET: Int = 0xFF
private const val BYTE_BITS: Int = 8
private const val HEX_RADIX: Int = 16
private const val MAXIMUM_GROUP_DIGITS: Int = 4
private const val MAXIMUM_OCTET_DIGITS: Int = 3
private const val COMPRESSION: String = "::"

internal object IpAddresses {
    val SIZES: Set<Int> = setOf(IPV4, IPV4 * 2, IPV6, IPV6 * 2)

    fun parseOrNull(text: String): ByteString? = ipv4OrNull(text) ?: ipv6OrNull(text)

    fun format(bytes: ByteString): String {
        val size = IPV6.takeIf { bytes.size >= IPV6 } ?: IPV4
        val address = formatAddress(bytes.substring(startIndex = 0, endIndex = size))
        val mask = bytes.substring(startIndex = size).takeIf { rest -> rest.size == size }
        val masked = mask?.let { found -> "$address/${formatAddress(found)}" }
        return masked ?: address
    }

    private fun formatAddress(bytes: ByteString): String {
        val isIpv4 = bytes.size == IPV4
        return listOf(::formatIpv6, ::formatIpv4)[isIpv4.compareTo(false)](bytes)
    }

    private fun ipv4OrNull(text: String): ByteString? {
        val parts = text.split('.').takeIf { found -> found.size == IPV4 } ?: return null
        val octets = parts.mapNotNull { part -> octetOrNull(part) }
        return octets.takeIf { found -> found.size == IPV4 }?.let { found -> ByteString(found.toByteArray()) }
    }

    private fun octetOrNull(part: String): Byte? {
        val hasDigits = part.length in 1..MAXIMUM_OCTET_DIGITS && part.all { char -> char in '0'..'9' }
        val isCanonical = hasDigits && (part.length == 1 || part[0] != '0')
        val value = part.takeIf { isCanonical }?.toInt()
        return value?.takeIf { found -> found <= OCTET }?.toByte()
    }

    private fun ipv6OrNull(text: String): ByteString? {
        val halves = text.split(COMPRESSION)
        val head = groupsOrNull(halves.first())
        val tail = halves.getOrNull(1)?.let { found -> groupsOrNull(found) }
        val count = (head?.size ?: GROUPS) + (tail?.size ?: 0)
        val isFull = halves.size == 1 && count == GROUPS
        val isCompressed = halves.size == 2 && tail != null && count < GROUPS
        val isValid = head != null && (isFull || isCompressed)
        val groups = head?.takeIf { isValid }
        val filled = groups?.let { found -> found + List(GROUPS - count) { 0 } + tail.orEmpty() }
        return filled?.let { found -> bytesOf(found) }
    }

    private fun bytesOf(groups: List<Int>): ByteString {
        val bytes = groups.flatMap { group -> listOf((group shr BYTE_BITS).toByte(), group.toByte()) }
        return ByteString(bytes.toByteArray())
    }

    private fun groupsOrNull(text: String): List<Int>? {
        val parts = text.split(':').takeUnless { text.isEmpty() } ?: return emptyList()
        val groups = parts.mapNotNull { part -> groupOrNull(part) }
        return groups.takeIf { found -> found.size == parts.size }
    }

    private fun groupOrNull(part: String): Int? {
        val isHex = part.length in 1..MAXIMUM_GROUP_DIGITS && part.all { char -> char.isHexDigit() }
        val value = part.takeIf { isHex }?.toInt(HEX_RADIX)
        return value
    }

    private fun formatIpv4(bytes: ByteString): String =
        (0 until IPV4).joinToString(".") { index -> (bytes[index].toInt() and OCTET).toString() }

    private fun formatIpv6(bytes: ByteString): String {
        val groups = (0 until GROUPS).map { index -> groupAt(bytes, index) }
        val texts = groups.map { group -> group.toString(HEX_RADIX) }
        val run = longestZeroRun(groups)
        val compressed = run?.let { (start, end) ->
            joined(texts = texts, from = 0, to = start) + COMPRESSION + joined(texts = texts, from = end, to = GROUPS)
        }
        return compressed ?: texts.joinToString(":")
    }

    private fun joined(texts: List<String>, from: Int, to: Int): String {
        val part = texts.subList(fromIndex = from, toIndex = to)
        return part.joinToString(":")
    }

    private fun groupAt(bytes: ByteString, index: Int): Int {
        val high = bytes[index * 2].toInt() and OCTET
        val low = bytes[index * 2 + 1].toInt() and OCTET
        return (high shl BYTE_BITS) or low
    }

    private fun longestZeroRun(groups: List<Int>): Pair<Int, Int>? {
        var best: Pair<Int, Int>? = null
        var start = 0
        while (start < GROUPS) {
            val end = (start until GROUPS).firstOrNull { index -> groups[index] != 0 } ?: GROUPS
            val length = end - start
            val bestLength = best?.let { (from, to) -> to - from } ?: 1
            if (length > bestLength) best = start to end
            start = end + 1
        }
        return best
    }

    private fun Char.isHexDigit(): Boolean = this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
}
