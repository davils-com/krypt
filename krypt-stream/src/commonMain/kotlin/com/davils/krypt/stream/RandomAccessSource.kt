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

import kotlinx.io.bytestring.ByteString

/**
 * Bytes that can be read at any offset, such as a file, an object in an object store with range requests or a blob in
 * a database; the application implements it, krypt never opens a file.
 *
 * @since 1.0.0
 */
public interface RandomAccessSource {
    /**
     * The number of bytes.
     *
     * @since 1.0.0
     */
    public val size: Long

    /**
     * Reads [length] bytes at [offset].
     *
     * @param offset where to start, at least 0.
     * @param length how many bytes, so that `offset + length` is at most [size].
     * @return the bytes; fewer than [length] only at the end.
     * @since 1.0.0
     */
    public suspend fun read(offset: Long, length: Int): ByteString
}
