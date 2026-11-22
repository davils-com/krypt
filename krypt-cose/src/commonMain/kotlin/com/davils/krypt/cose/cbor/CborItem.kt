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

import com.davils.krypt.cose.internal.CborWriter
import kotlinx.io.bytestring.ByteString

/**
 * A data item of CBOR by RFC 8949: an integer, a byte or text string, an array, a map, a tag, a simple value or a
 * floating-point number.
 *
 * Every item is immutable and safe to share between threads. Two items are equal when they are the same data model
 * value, which is also when their deterministic encodings by RFC 8949 section 4.2.1 are equal, apart from the
 * payloads of NaN, which [CborFloat] compares bit by bit.
 *
 * @since 1.0.0
 */
public sealed class CborItem {
    internal abstract fun write(writer: CborWriter)

    internal open fun bytesOrNull(): ByteString? = null

    internal open fun textOrNull(): String? = null

    internal open fun integerOrNull(): CborInteger? = null

    internal open fun itemsOrNull(): List<CborItem>? = null

    internal open fun mapOrNull(): CborMap? = null

    internal open fun tagOrNull(): CborTag? = null

    internal open fun simpleOrNull(): CborSimple? = null

    internal open fun floatOrNull(): CborFloat? = null
}
