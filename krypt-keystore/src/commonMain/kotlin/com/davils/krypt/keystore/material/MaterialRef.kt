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

package com.davils.krypt.keystore.material

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import kotlin.jvm.JvmInline

private const val MAXIMUM_NAME: Int = 4_096

/**
 * The name of key material in a [MaterialSource] or a [MaterialSink], such as a path, a key of a secret store or the
 * name of a mounted secret; krypt never interprets it.
 *
 * @property name the name.
 * @constructor Checks the name.
 * @throws IllegalArgumentException if [name] is blank or longer than 4,096 characters.
 * @since 1.0.0
 */
@JvmInline
public value class MaterialRef(public val name: String) {
    init {
        require(name.isNotBlank() && name.length <= MAXIMUM_NAME) {
            "A material name has 1 to $MAXIMUM_NAME characters"
        }
    }

    /**
     * Shows the name, escaped.
     *
     * @return the reference as text.
     * @since 1.0.0
     */
    @OptIn(DavilsInternal::class)
    override fun toString(): String = "MaterialRef(${SafeText.text(name)})"
}
