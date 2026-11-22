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

/**
 * Reads key material for krypt, which never opens a file itself; the application implements it over its file
 * system, a secret store or a vault.
 *
 * @since 1.0.0
 */
public fun interface MaterialSource {
    /**
     * Reads the material under [ref].
     *
     * A source should stop reading past [maximumBytes] and may answer with more, which krypt then refuses. Exceptions
     * are not caught by krypt: a source reports what it can as [MaterialRead.Missing] or
     * [MaterialRead.Unavailable].
     *
     * @param ref the reference.
     * @param maximumBytes the most bytes krypt accepts.
     * @return what was found.
     * @since 1.0.0
     */
    public suspend fun read(ref: MaterialRef, maximumBytes: Int): MaterialRead
}
