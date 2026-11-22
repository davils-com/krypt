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
 * A stream of bytes krypt writes to, which the caller implements over its own I/O.
 *
 * krypt writes to a sink from one coroutine at a time. A sink must not keep [write]'s array, which krypt reuses.
 *
 * @since 1.0.0
 */
public fun interface ByteSink {
    /**
     * Writes [length] bytes of [source] from [offset] on.
     *
     * @param source the bytes.
     * @param offset where the bytes start in [source].
     * @param length the number of bytes.
     * @since 1.0.0
     */
    public suspend fun write(source: ByteArray, offset: Int, length: Int)
}
