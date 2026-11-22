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

package com.davils.krypt.core.io

import com.davils.krypt.core.fixture.bytes
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.flow.toList
import kotlinx.io.bytestring.ByteString

private const val THREE_BYTES: String = "010203"
private const val THREE: Int = 3
private const val TARGET_SIZE: Int = 5
private const val SINK_LIMIT: Int = 300
private const val FIRST_WRITE: Int = 200
private const val GROWTH: Int = 60

class ByteStreamsTest : FunSpec({
    test("an array source yields its bytes and then the end") {
        val source = bytes(THREE_BYTES).asByteSource()
        val target = ByteArray(TARGET_SIZE)
        source.readFully(target) shouldBe THREE
        val again = bytes(THREE_BYTES).asByteSource()
        again.readFully(target = target, offset = 0, length = 2) shouldBe 2
        source.read(target = target, offset = 0, length = 1) shouldBe -1
        ByteString(data = target, startIndex = 0, endIndex = THREE) shouldBe ByteString(bytes(THREE_BYTES))
    }

    test("read all collects the whole source up to its limit") {
        val source = ByteString(bytes(THREE_BYTES))
        source.asByteSource().readAll(maximum = THREE) shouldBe source
        val empty = ByteString()
        empty.asByteSource().readAll(maximum = 0) shouldBe empty
        val failure = shouldThrow<ByteLimitException> { source.asByteSource().readAll(maximum = 2) }
        failure.maximum shouldBe 2L
    }

    test("read all with the largest limit reads a short source without overflowing the chunk size") {
        val source = ByteString(bytes(THREE_BYTES))
        source.asByteSource().readAll(maximum = Int.MAX_VALUE) shouldBe source
    }

    test("a flow carries the source in chunks") {
        val source = ByteString(bytes("0102030405")).asByteSource()
        val flow = source.asFlow(chunkSize = 2)
        val chunks = flow.toList()
        chunks shouldBe listOf(ByteString(bytes("0102")), ByteString(bytes("0304")), ByteString(bytes("05")))
        val empty = ByteString().asByteSource()
        shouldThrow<IllegalArgumentException> { empty.asFlow(chunkSize = 0) }
    }

    test("a buffer sink collects, grows, refuses past its limit and wipes") {
        val sink = BufferSink(maximum = SINK_LIMIT)
        sink.write(source = ByteArray(FIRST_WRITE), offset = 0, length = FIRST_WRITE)
        sink.append(source = bytes("0203"), offset = 1, length = 1)
        sink.size shouldBe FIRST_WRITE + 1
        sink.append(ByteArray(GROWTH))
        sink.size shouldBe FIRST_WRITE + 1 + GROWTH
        val collected = sink.toByteString()
        collected[FIRST_WRITE] shouldBe bytes("03").single()
        shouldThrow<ByteLimitException> { sink.append(ByteArray(SINK_LIMIT - FIRST_WRITE)) }
        sink.size shouldBe FIRST_WRITE + 1 + GROWTH
        sink.toString() shouldBe "BufferSink(size=261, maximum=300)"
        sink.wipe()
        sink.size shouldBe 0
        shouldThrow<IllegalArgumentException> { BufferSink(-1) }
    }
})
