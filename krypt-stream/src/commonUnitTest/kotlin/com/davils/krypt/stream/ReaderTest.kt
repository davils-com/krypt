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

package com.davils.krypt.stream

import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.stream.fixture.SEGMENT
import com.davils.krypt.stream.fixture.aeadKeyset
import com.davils.krypt.stream.fixture.bytes
import com.davils.krypt.stream.fixture.containers
import com.davils.krypt.stream.fixture.flipped
import com.davils.krypt.stream.fixture.keysets
import com.davils.krypt.stream.fixture.utf8
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlinx.io.bytestring.ByteString

private const val SEGMENTS: Long = 4L
private const val LAST: Long = 3L
private const val REST: Int = 100
private const val SIZE: Int = 3 * 65_536 + 100
private const val SEGMENT_SIZE: Int = 65_536
private const val OFFSET: Long = 65_500L
private const val LENGTH: Int = 200

class ReaderTest : FunSpec({
    test("a reader decrypts any range and only the segments it needs") {
        val keyset = aeadKeyset()
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        val credentials = listOf(Credential.Key(keysets.aead(keyset)))
        val reader = checkNotNull(containers.open(container.asRandomAccessSource(), credentials).getOrNull())
        reader.segments shouldBe SEGMENTS
        reader.segmentSize shouldBe SEGMENT_SIZE
        reader.plaintextBytes shouldBe SIZE.toLong()
        val expected = bytes(SIZE).substring(startIndex = OFFSET.toInt(), endIndex = OFFSET.toInt() + LENGTH)
        reader.read(OFFSET, LENGTH) shouldBe expected
        reader.read(0L, 0) shouldBe ByteString()
        reader.read(SIZE.toLong() - 1, 1) shouldBe bytes(SIZE).substring(startIndex = SIZE - 1, endIndex = SIZE)
        reader.segment(LAST)?.size shouldBe REST
        reader.toString() shouldBe "ContainerReader(segments=4, plaintextBytes=$SIZE)"
        shouldThrow<IllegalArgumentException> { reader.segment(SEGMENTS) }
        shouldThrow<IllegalArgumentException> { reader.read(SIZE.toLong(), 1) }
        shouldThrow<IllegalArgumentException> { reader.read(-1L, 1) }
        reader.close()
        shouldThrow<IllegalStateException> { reader.segment(0L) }
    }

    test("a changed segment is refused where it is read") {
        val keyset = aeadKeyset()
        val container = containers.encrypt(
            plaintext = bytes(SIZE),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        val changed = flipped(container, container.size - 1)
        val reader = checkNotNull(
            containers.open(changed.asRandomAccessSource(), listOf(Credential.Key(keysets.aead(keyset)))).getOrNull(),
        )
        reader.segment(0L)?.size shouldBe SEGMENT_SIZE
        reader.segment(LAST) shouldBe null
        reader.read(SIZE.toLong() - 2, 2) shouldBe null
    }

    test("a container cut to a size no segment fits is refused") {
        val keyset = aeadKeyset()
        val container = containers.encrypt(
            plaintext = bytes(SEGMENT),
            recipients = listOf(Recipient.Key(keysets.aead(keyset))),
        )
        val credentials = listOf(Credential.Key(keysets.aead(keyset)))
        val cut = container.substring(startIndex = 0, endIndex = container.size - SEGMENT - 1)
        containers.open(cut.asRandomAccessSource(), credentials).failureOrNull() shouldBe StreamFailure.Malformed
        val outcome1 = containers.open(
            utf8("junk").asRandomAccessSource(),
            credentials,
        )
        outcome1.failureOrNull() shouldBe StreamFailure.Malformed
        val source = container.asRandomAccessSource()
        source.read(offset = container.size.toLong(), length = 1) shouldBe ByteString()
        source.size shouldBe container.size.toLong()
        containers.open(source, credentials, utf8("other")).failureOrNull() shouldBe StreamFailure.DecryptionFailed
    }
})
