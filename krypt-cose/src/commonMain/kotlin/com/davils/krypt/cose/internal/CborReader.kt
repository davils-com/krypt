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

package com.davils.krypt.cose.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborBytes
import com.davils.krypt.cose.cbor.CborFailure
import com.davils.krypt.cose.cbor.CborFloat
import com.davils.krypt.cose.cbor.CborInteger
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborLimits
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.cbor.CborMode
import com.davils.krypt.cose.cbor.CborSimple
import com.davils.krypt.cose.cbor.CborTag
import com.davils.krypt.cose.cbor.CborText
import kotlinx.io.bytestring.ByteString

internal class CborReader private constructor(
    private val bytes: ByteArray,
    private val limits: CborLimits,
    mode: CborMode,
) {
    private val isDeterministic = mode == CborMode.Deterministic
    private var position = 0
    private var items = 0

    private fun readItem(depth: Int): CborItem {
        items += 1
        ensure(items <= limits.maximumItems, CborFailure.LimitExceeded)
        val start = position
        val initial = readByte()
        val major = MajorType.entries[initial ushr MAJOR_SHIFT]
        val info = initial and INFO_MASK
        if (info == INDEFINITE) refuse(listOf(CborFailure.Malformed, CborFailure.IndefiniteLength)[major.index()])
        return when (major) {
            MajorType.Unsigned -> CborInteger.unsigned(argument(info))
            MajorType.Negative -> CborInteger.negative(argument(info))
            MajorType.Bytes -> CborBytes(ByteString(readString(info)))
            MajorType.Text -> readText(info)
            MajorType.Array -> readArray(info, depth)
            MajorType.Map -> readMap(info, depth)
            MajorType.Tag -> readTag(info, depth)
            MajorType.Simple -> readSimple(info, start)
        }
    }

    private fun MajorType.index(): Int = isIndefiniteAllowed.compareTo(false)

    private fun argument(info: Int): ULong {
        if (info < ONE_BYTE) return info.toULong()
        ensure(info <= EIGHT_BYTES, CborFailure.Malformed)
        val width = info - ONE_BYTE
        val value = readUnsigned(1 shl width)
        ensure(!isDeterministic || value >= SHORTEST[width], CborFailure.NotDeterministic)
        return value
    }

    private fun count(info: Int, limit: Int, perItem: Int): Int {
        val value = argument(info)
        ensure(value <= limit.toULong(), CborFailure.LimitExceeded)
        val remaining = (bytes.size - position).toULong()
        ensure(value * perItem.toULong() <= remaining, CborFailure.Truncated)
        return value.toInt()
    }

    private fun readString(info: Int): ByteArray {
        val length = count(info = info, limit = limits.maximumStringBytes, perItem = 1)
        val slice = bytes.copyOfRange(fromIndex = position, toIndex = position + length)
        position += length
        return slice
    }

    private fun readText(info: Int): CborText {
        val slice = readString(info)
        ensure(Utf8.isValid(slice), CborFailure.InvalidText)
        return CborText(slice.decodeToString())
    }

    private fun readArray(info: Int, depth: Int): CborArray {
        ensure(depth < limits.maximumDepth, CborFailure.LimitExceeded)
        val size = count(info = info, limit = limits.maximumItems, perItem = 1)
        return CborArray(List(size) { readItem(depth + 1) })
    }

    private fun readMap(info: Int, depth: Int): CborMap {
        ensure(depth < limits.maximumDepth, CborFailure.LimitExceeded)
        val size = count(info = info, limit = limits.maximumMapEntries, perItem = 2)
        val keys = ArrayList<ByteString>(size)
        val entries = List(size) {
            val start = position
            val key = readItem(depth + 1)
            val encoded = ByteString(bytes.copyOfRange(fromIndex = start, toIndex = position))
            keys += encoded.takeIf { isDeterministic } ?: CborWriter.encode(key)
            key to readItem(depth + 1)
        }
        checkKeys(keys)
        return CborMap(entries)
    }

    private fun checkKeys(keys: List<ByteString>) {
        val sorted = keys.takeUnless { isDeterministic }?.sortedWith { first, second ->
            Bytes.compare(first = first, second = second)
        }
        val ordered = sorted ?: keys
        ordered.zipWithNext().forEach { (first, second) ->
            val order = Bytes.compare(first = first, second = second)
            ensure(order != 0, CborFailure.DuplicateKey)
            ensure(order < 0, CborFailure.NotDeterministic)
        }
    }

    private fun readTag(info: Int, depth: Int): CborTag {
        val number = argument(info)
        ensure(depth < limits.maximumDepth, CborFailure.LimitExceeded)
        return CborTag(number = number, content = readItem(depth + 1))
    }

    private fun readSimple(info: Int, start: Int): CborItem {
        if (info < ONE_BYTE) return CborSimple(info)
        ensure(info < BREAK_RESERVED, CborFailure.Malformed)
        val value = readUnsigned(1 shl info - ONE_BYTE)
        val simple = value.takeIf { info == ONE_BYTE }?.let { found -> extendedSimple(found) }
        return simple ?: readFloat(info = info, value = value, start = start)
    }

    private fun extendedSimple(value: ULong): CborSimple {
        ensure(value >= FIRST_EXTENDED, CborFailure.Malformed)
        return CborSimple(value.toInt())
    }

    private fun readFloat(info: Int, value: ULong, start: Int): CborFloat {
        val number = listOf(
            Floats.ofHalf(value.toInt()),
            Floats.ofSingle(value.toInt()),
            Double.fromBits(value.toLong()),
        )[info - TWO_BYTES]
        val encoded = bytes.copyOfRange(fromIndex = start, toIndex = position)
        ensure(!isDeterministic || Floats.encode(number).contentEquals(encoded), CborFailure.NotDeterministic)
        return CborFloat(number)
    }

    private fun readByte(): Int {
        ensure(position < bytes.size, CborFailure.Truncated)
        val byte = bytes[position].toInt() and BYTE_MASK
        position += 1
        return byte
    }

    private fun readUnsigned(width: Int): ULong {
        ensure(position + width <= bytes.size, CborFailure.Truncated)
        var value = 0UL
        repeat(width) { value = (value shl Byte.SIZE_BITS) or readByte().toULong() }
        return value
    }

    private fun ensure(condition: Boolean, failure: CborFailure) {
        if (!condition) refuse(failure)
    }

    private fun refuse(failure: CborFailure): Nothing = throw CborException(failure)

    companion object {
        private const val MAJOR_SHIFT: Int = 5
        private const val INFO_MASK: Int = 0x1f
        private const val BYTE_MASK: Int = 0xff
        private const val ONE_BYTE: Int = 24
        private const val TWO_BYTES: Int = 25
        private const val EIGHT_BYTES: Int = 27
        private const val BREAK_RESERVED: Int = 28
        private const val INDEFINITE: Int = 31
        private const val FIRST_EXTENDED: ULong = 32UL
        private val SHORTEST: List<ULong> = listOf(24UL, 0x100UL, 0x1_0000UL, 0x1_0000_0000UL)

        fun decode(encoded: ByteString, limits: CborLimits, mode: CborMode): Outcome<CborItem, CborFailure> {
            if (encoded.size > limits.maximumBytes) return Outcome.Failure(CborFailure.LimitExceeded)
            val reader = CborReader(bytes = encoded.toByteArray(), limits = limits, mode = mode)
            return try {
                val item = reader.readItem(depth = 0)
                reader.ensure(reader.position == reader.bytes.size, CborFailure.TrailingData)
                Outcome.Success(item)
            } catch (refusal: CborException) {
                Outcome.Failure(refusal.failure)
            }
        }

        fun decodeOrNull(encoded: ByteString, limits: CborLimits, mode: CborMode): CborItem? =
            decode(encoded = encoded, limits = limits, mode = mode).getOrNull()
    }
}
