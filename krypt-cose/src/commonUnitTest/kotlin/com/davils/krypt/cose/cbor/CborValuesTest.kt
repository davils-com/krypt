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

package com.davils.krypt.cose.cbor

import com.davils.krypt.cose.fixture.hex
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

private const val OTHER: String = "other"
private const val LABEL: Long = 7

class CborValuesTest : FunSpec({
    test("integers keep the full range of 64 bits") {
        CborInteger.of(Long.MAX_VALUE).toLongOrNull() shouldBe Long.MAX_VALUE
        CborInteger.of(Long.MIN_VALUE).toLongOrNull() shouldBe Long.MIN_VALUE
        CborInteger.unsigned(ULong.MAX_VALUE).toLongOrNull() shouldBe null
        CborInteger.negative(ULong.MAX_VALUE).toLongOrNull() shouldBe null
        CborInteger.negative(ULong.MAX_VALUE).toString() shouldBe "-18446744073709551616"
        CborInteger.negative(ULong.MAX_VALUE - 1UL).toString() shouldBe "-18446744073709551615"
        CborInteger.of(-1).toString() shouldBe "-1"
        CborInteger.of(1).toString() shouldBe "1"
        CborInteger.of(1).isNegative shouldBe false
        CborInteger.of(-1).argument shouldBe 0UL
        CborInteger.of(1) shouldNotBe CborInteger.of(value = -2)
        CborInteger.of(1) shouldNotBe CborInteger.of(2)
        CborInteger.of(1).equals(OTHER) shouldBe false
        CborInteger.of(1).hashCode() shouldBe CborInteger.unsigned(1UL).hashCode()
    }

    test("strings, arrays, maps, tags, simple values and floats compare by value") {
        CborBytes(hex("01")) shouldBe CborBytes(hex("01"))
        CborBytes(hex("01")) shouldNotBe CborBytes(hex("02"))
        CborBytes(hex("01")).equals(OTHER) shouldBe false
        CborBytes(hex("01")).hashCode() shouldBe CborBytes(hex("01")).hashCode()
        CborBytes(hex("0102")).toString() shouldBe "h'0102'"
        CborText("a") shouldBe CborText("a")
        CborText("a") shouldNotBe CborText("b")
        CborText("a").equals(OTHER) shouldBe false
        CborText("a").hashCode() shouldBe "a".hashCode()
        CborText("a\nb").toString() shouldBe """${'"'}a\nb${'"'}"""
        shouldThrow<IllegalArgumentException> { CborText("\ud800") }
        shouldThrow<IllegalArgumentException> { CborText("\udc00") }
        shouldThrow<IllegalArgumentException> { CborText("\ud800a") }
        val array = CborArray.of(CborInteger.of(1), CborText("a"))
        array.size shouldBe 2
        array[1] shouldBe CborText("a")
        array shouldBe CborArray(listOf(CborInteger.of(1), CborText("a")))
        array shouldNotBe CborArray.of()
        array.equals(OTHER) shouldBe false
        array.hashCode() shouldBe array.items.hashCode()
        array.toString() shouldBe "[1, \"a\"]"
        val map = CborMap.of(CborText("b") to CborInteger.of(1), CborInteger.of(LABEL) to CborSimple.True)
        map.keys shouldBe listOf(CborInteger.of(LABEL), CborText("b"))
        map.size shouldBe 2
        map[LABEL] shouldBe CborSimple.True
        map[CborText("b")] shouldBe CborInteger.of(1)
        map[CborText("c")] shouldBe null
        (CborText("b") in map) shouldBe true
        (CborText("c") in map) shouldBe false
        map shouldNotBe CborMap.Empty
        map.equals(OTHER) shouldBe false
        map.hashCode() shouldBe map.entries.hashCode()
        map.toString() shouldBe "{7: true, \"b\": 1}"
        shouldThrow<IllegalArgumentException> {
            CborMap.of(CborInteger.of(1) to CborInteger.of(1), CborInteger.of(1) to CborInteger.of(2))
        }
        val tag = CborTag(number = 1UL, content = CborInteger.of(1))
        tag shouldBe CborTag(number = 1UL, content = CborInteger.of(1))
        tag shouldNotBe CborTag(number = 2UL, content = CborInteger.of(1))
        tag shouldNotBe CborTag(number = 1UL, content = CborInteger.of(2))
        tag.equals(OTHER) shouldBe false
        tag.hashCode() shouldBe CborTag(number = 1UL, content = CborInteger.of(1)).hashCode()
        tag.toString() shouldBe "1(1)"
        CborSimple.of(true) shouldBe CborSimple.True
        CborSimple.of(false) shouldBe CborSimple.False
        CborSimple.True.isBoolean shouldBe true
        CborSimple.False.isBoolean shouldBe true
        CborSimple.Null.isBoolean shouldBe false
        CborSimple.Null.toString() shouldBe "null"
        CborSimple.Undefined.toString() shouldBe "undefined"
        CborSimple(value = 0).toString() shouldBe "simple(0)"
        CborSimple(value = 0).hashCode() shouldBe 0
        CborSimple(value = 0).equals(OTHER) shouldBe false
        shouldThrow<IllegalArgumentException> { CborSimple(value = 24) }
        shouldThrow<IllegalArgumentException> { CborSimple(value = 31) }
        shouldThrow<IllegalArgumentException> { CborSimple(value = -1) }
        shouldThrow<IllegalArgumentException> { CborSimple(value = 256) }
        CborFloat(value = Double.NaN) shouldBe CborFloat(value = Double.NaN)
        CborFloat(value = 0.0) shouldNotBe CborFloat(value = -0.0)
        CborFloat(value = 1.5).equals(OTHER) shouldBe false
        CborFloat(value = 1.5).hashCode() shouldBe CborFloat(value = 1.5).hashCode()
        CborFloat(value = 1.5).toString() shouldBe "1.5"
    }

    test("the typed accessors answer only for their own type") {
        val items = listOf(
            CborInteger.of(1),
            CborBytes(hex("01")),
            CborText("a"),
            CborArray.of(),
            CborMap.Empty,
            CborTag(number = 1UL, content = CborInteger.of(1)),
            CborSimple.True,
            CborFloat(value = 1.5),
        )
        items.map { item -> item.integerOrNull() != null } shouldBe listOf(true) + List(size = 7) { false }
        items.map { item -> item.bytesOrNull() != null } shouldBe listOf(false, true) + List(size = 6) { false }
        items.map { item -> item.textOrNull() != null } shouldBe
            listOf(false, false, true) + List(size = 5) { false }
        items.map { item -> item.itemsOrNull() != null } shouldBe
            List(size = 3) { false } + listOf(true) + List(size = 4) { false }
        items.map { item -> item.mapOrNull() != null } shouldBe
            List(size = 4) { false } + listOf(true) + List(size = 3) { false }
        items.map { item -> item.tagOrNull() != null } shouldBe
            List(size = 5) { false } + listOf(true) + List(size = 2) { false }
        items.map { item -> item.simpleOrNull() != null } shouldBe
            List(size = 6) { false } + listOf(true, false)
        items.map { item -> item.floatOrNull() != null } shouldBe List(size = 7) { false } + listOf(true)
    }
})
