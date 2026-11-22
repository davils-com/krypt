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

package com.davils.krypt.storage.blob

import com.davils.krypt.core.io.ByteSink
import com.davils.krypt.stream.RandomAccessSource

/**
 * Where encrypted objects are kept, implemented by the application over a file system, an object store such as S3,
 * a database or a cache; krypt never touches a file itself.
 *
 * The store sees only blinded keys and encrypted bytes. A key consists of the letters of base64url.
 *
 * @since 1.0.0
 */
public interface BlobStore {
    /**
     * Writes the object [key], replacing what was there once [content] returns.
     *
     * The replacement must be atomic: readers of the old object keep reading it until [content] returns, and when
     * [content] throws, the old object stays and the exception is passed on. A temporary object that is renamed at the
     * end, or the upload of an object store, does this.
     *
     * @param key the key.
     * @param content writes the bytes of the object into the sink it is given.
     * @since 1.0.0
     */
    public suspend fun write(key: String, content: suspend (ByteSink) -> Unit)

    /**
     * Opens the object [key] for reading at any offset.
     *
     * @param key the key.
     * @return the object, or null if there is none.
     * @since 1.0.0
     */
    public suspend fun open(key: String): RandomAccessSource?

    /**
     * Deletes the object [key].
     *
     * @param key the key.
     * @return true if an object was deleted.
     * @since 1.0.0
     */
    public suspend fun delete(key: String): Boolean
}
