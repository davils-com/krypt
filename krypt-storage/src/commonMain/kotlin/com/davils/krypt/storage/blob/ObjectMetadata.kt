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

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import kotlin.time.Instant

private const val MAXIMUM_ATTRIBUTES: Int = 32
private const val MAXIMUM_TEXT: Int = 1_024

/**
 * What an [EncryptedBlobStore] keeps about an object, encrypted with it: the store sees none of it.
 *
 * @property name the name of the object.
 * @property version the version, which grows with every put.
 * @property contentType the media type.
 * @property createdAt when this version was put.
 * @param attributes further facts of the application; at most 32.
 * @constructor Describes [name] at [version].
 * @throws IllegalArgumentException if there are more than 32 attributes or a text is longer than 1024 characters.
 * @since 1.0.0
 */
@OptIn(DavilsInternal::class)
public class ObjectMetadata(
    public val name: String,
    public val version: Long,
    public val contentType: String,
    public val createdAt: Instant,
    attributes: Map<String, String> = emptyMap(),
) {
    /**
     * Further facts of the application, sorted by name.
     *
     * @since 1.0.0
     */
    public val attributes: Map<String, String> = buildMap {
        attributes.keys.sorted().forEach { key -> put(key, attributes.getValue(key)) }
    }

    init {
        require(attributes.size <= MAXIMUM_ATTRIBUTES) { "An object has at most $MAXIMUM_ATTRIBUTES attributes" }
        val texts = listOf(name, contentType) + attributes.keys + attributes.values
        require(
            texts.all { text -> text.length <= MAXIMUM_TEXT },
        ) { "A text of an object has at most $MAXIMUM_TEXT characters" }
    }

    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] describes the same version.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is ObjectMetadata &&
        listOf(name, version, contentType, createdAt, attributes) ==
        listOf(other.name, other.version, other.contentType, other.createdAt, other.attributes)

    /**
     * Hashes the name and the version.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(name, version).hashCode()

    /**
     * Shows the name escaped, the version and the type.
     *
     * @return the metadata as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "ObjectMetadata(${SafeText.text(name)}, version=$version, type=${SafeText.text(contentType)})"
}
