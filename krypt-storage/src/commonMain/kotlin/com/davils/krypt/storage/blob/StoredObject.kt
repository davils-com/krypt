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

import com.davils.krypt.stream.ContainerReader

/**
 * An object opened for reading at any offset: its [metadata] and a [reader] of its content, which the caller closes.
 *
 * @property metadata what is known about the object.
 * @property reader the reader of the content.
 * @since 1.0.0
 */
public class StoredObject internal constructor(
    public val metadata: ObjectMetadata,
    public val reader: ContainerReader,
) {
    /**
     * Closes the reader and wipes its keys.
     *
     * @since 1.0.0
     */
    public fun close() {
        reader.close()
    }

    /**
     * Shows the metadata.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "StoredObject($metadata)"
}
