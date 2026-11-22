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

/**
 * A stream of bytes krypt reads from, such as a file, an object in a store or the body of a request, which the caller
 * implements over its own I/O; krypt never opens a file or a connection itself.
 *
 * krypt reads a source from one coroutine at a time and never after it returned -1.
 *
 * @since 1.0.0
 */
public fun interface ByteSource {
    /**
     * Reads up to [length] bytes into [target] from [offset] on.
     *
     * @param target the array to read into.
     * @param offset where the bytes go in [target].
     * @param length the most bytes to read, at least 1.
     * @return the number of bytes read, at least 1, or -1 at the end of the stream.
     * @since 1.0.0
     */
    public suspend fun read(target: ByteArray, offset: Int, length: Int): Int
}
