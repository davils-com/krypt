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

import com.davils.krypt.cose.fixture.failure
import com.davils.krypt.cose.fixture.hex
import com.davils.krypt.cose.fixture.hexOf
import com.davils.krypt.cose.fixture.value
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe

private fun int(value: Long): CborItem = CborInteger.of(value)

private fun text(value: String): CborItem = CborText(value)

private fun bytes(value: String): CborItem = CborBytes(hex(value))

private val APPENDIX_A: List<Pair<CborItem, String>> = listOf(
    int(value = 0) to "00",
    int(value = 1) to "01",
    int(value = 10) to "0A",
    int(value = 23) to "17",
    int(value = 24) to "1818",
    int(value = 25) to "1819",
    int(value = 100) to "1864",
    int(value = 1_000) to "1903E8",
    int(value = 1_000_000) to "1A000F4240",
    int(value = 1_000_000_000_000) to "1B000000E8D4A51000",
    CborInteger.unsigned(ULong.MAX_VALUE) to "1BFFFFFFFFFFFFFFFF",
    CborTag(number = 2UL, content = bytes(value = "010000000000000000")) to "C249010000000000000000",
    CborInteger.negative(ULong.MAX_VALUE) to "3BFFFFFFFFFFFFFFFF",
    CborTag(number = 3UL, content = bytes(value = "010000000000000000")) to "C349010000000000000000",
    int(value = -1) to "20",
    int(value = -10) to "29",
    int(value = -100) to "3863",
    int(value = -1_000) to "3903E7",
    CborFloat(value = 0.0) to "F90000",
    CborFloat(value = -0.0) to "F98000",
    CborFloat(value = 1.0) to "F93C00",
    CborFloat(value = 1.1) to "FB3FF199999999999A",
    CborFloat(value = 1.5) to "F93E00",
    CborFloat(value = 65_504.0) to "F97BFF",
    CborFloat(value = 100_000.0) to "FA47C35000",
    CborFloat(value = 3.4028234663852886e38) to "FA7F7FFFFF",
    CborFloat(value = 1.0e300) to "FB7E37E43C8800759C",
    CborFloat(value = 5.960464477539063e-8) to "F90001",
    CborFloat(value = 0.00006103515625) to "F90400",
    CborFloat(value = -4.0) to "F9C400",
    CborFloat(value = -4.1) to "FBC010666666666666",
    CborFloat(value = Double.POSITIVE_INFINITY) to "F97C00",
    CborFloat(value = Double.NaN) to "F97E00",
    CborFloat(value = Double.NEGATIVE_INFINITY) to "F9FC00",
    CborSimple.False to "F4",
    CborSimple.True to "F5",
    CborSimple.Null to "F6",
    CborSimple.Undefined to "F7",
    CborSimple(value = 16) to "F0",
    CborSimple(value = 255) to "F8FF",
    CborTag(number = 0UL, content = text(value = "2013-03-21T20:04:00Z")) to
        "C074323031332D30332D32315432303A30343A30305A",
    CborTag(number = 1UL, content = int(value = 1_363_896_240)) to "C11A514B67B0",
    CborTag(number = 1UL, content = CborFloat(value = 1_363_896_240.5)) to "C1FB41D452D9EC200000",
    CborTag(number = 23UL, content = bytes(value = "01020304")) to "D74401020304",
    CborTag(number = 24UL, content = bytes(value = "6449455446")) to "D818456449455446",
    CborTag(number = 32UL, content = text(value = "http://www.example.com")) to
        "D82076687474703A2F2F7777772E6578616D706C652E636F6D",
    bytes(value = "") to "40",
    bytes(value = "01020304") to "4401020304",
    text(value = "") to "60",
    text(value = "a") to "6161",
    text(value = "IETF") to "6449455446",
    text(value = "\"\\") to "62225C",
    text(value = "ü") to "62C3BC",
    text(value = "水") to "63E6B0B4",
    text(value = "𐅑") to "64F0908591",
    CborArray.of() to "80",
    CborArray.of(int(value = 1), int(value = 2), int(value = 3)) to "83010203",
    CborArray.of(
        int(value = 1),
        CborArray.of(int(value = 2), int(value = 3)),
        CborArray.of(int(value = 4), int(value = 5)),
    ) to "8301820203820405",
    CborArray((1L..25L).map { number -> int(number) }) to
        "98190102030405060708090A0B0C0D0E0F101112131415161718181819",
    CborMap.Empty to "A0",
    CborMap.of(int(value = 1) to int(value = 2), int(value = 3) to int(value = 4)) to "A201020304",
    CborMap.of(
        text(value = "a") to int(value = 1),
        text(value = "b") to CborArray.of(int(value = 2), int(value = 3)),
    ) to "A26161016162820203",
    CborArray.of(text(value = "a"), CborMap.of(text(value = "b") to text(value = "c"))) to "826161A161626163",
    CborMap(listOf("a", "b", "c", "d", "e").map { key -> text(key) to text(key.uppercase()) }) to
        "A56161614161626142616361436164614461656145",
)

private val NOT_PREFERRED: List<String> = listOf(
    "FA7F800000",
    "FA7FC00000",
    "FAFF800000",
    "FB7FF0000000000000",
    "FB7FF8000000000000",
    "FBFFF0000000000000",
    "FB3FF0000000000000",
)

private val INDEFINITE: List<String> = listOf(
    "5F42010243030405FF",
    "7F657374726561646D696E67FF",
    "9FFF",
    "9F018202039F0405FFFF",
    "BF61610161629F0203FFFF",
)

class CborCodecTest : FunSpec({
    test("the examples of RFC 8949 appendix A encode and decode deterministically") {
        APPENDIX_A.forEach { (item, encoded) ->
            hexOf(Cbor.encode(item)) shouldBe encoded
            Cbor.decode(hex(encoded)).value() shouldBe item
        }
    }

    test("floats that are not as short as they could be are not deterministic") {
        NOT_PREFERRED.forEach { encoded ->
            Cbor.decode(hex(encoded)).failure() shouldBe CborFailure.NotDeterministic
            val decoded = Cbor.decode(encoded = hex(encoded), mode = CborMode.Relaxed).value()
            (decoded is CborFloat) shouldBe true
        }
    }

    test("indefinite lengths are never read") {
        INDEFINITE.forEach { encoded ->
            Cbor.decode(hex(encoded)).failure() shouldBe CborFailure.IndefiniteLength
            Cbor.decode(encoded = hex(encoded), mode = CborMode.Relaxed).failure() shouldBe CborFailure.IndefiniteLength
        }
    }

    test("the relaxed mode accepts longer arguments and unsorted keys but not duplicates") {
        val relaxed = { encoded: String -> Cbor.decode(encoded = hex(encoded), mode = CborMode.Relaxed) }
        relaxed("1817").value() shouldBe int(value = 23)
        relaxed("190017").value() shouldBe int(value = 23)
        relaxed("1A00000017").value() shouldBe int(value = 23)
        relaxed("1B0000000000000017").value() shouldBe int(value = 23)
        relaxed(
            "A203040102",
        ).value() shouldBe CborMap.of(int(value = 1) to int(value = 2), int(value = 3) to int(value = 4))
        relaxed("A2010218010303").failure() shouldBe CborFailure.DuplicateKey
        relaxed("A201020102").failure() shouldBe CborFailure.DuplicateKey
        Cbor.decode(hex("A201020102")).failure() shouldBe CborFailure.DuplicateKey
        Cbor.decode(hex("A203040102")).failure() shouldBe CborFailure.NotDeterministic
        listOf("1817", "190017", "1A00000017", "1B0000000000000017", "D81701", "F81F").forEach { encoded ->
            Cbor.decode(hex(encoded)).failure() shouldBe failureOfShortest(encoded)
        }
    }
})

private fun failureOfShortest(encoded: String): CborFailure =
    CborFailure.Malformed.takeIf { encoded == "F81F" } ?: CborFailure.NotDeterministic
