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

package com.davils.krypt.keyset

/**
 * The state of a key in its lifecycle.
 *
 * @since 1.0.0
 */
public enum class KeyStatus {
    /**
     * The key is in use: the primary key protects new data, every enabled key opens and verifies what it protected.
     *
     * @since 1.0.0
     */
    Enabled,

    /**
     * The key is kept but used for nothing, so that turning it off can be undone before the key is destroyed.
     *
     * @since 1.0.0
     */
    Disabled,

    /**
     * The material of the key is wiped; only its id is left, so that nothing the key protected can be opened again.
     *
     * @since 1.0.0
     */
    Destroyed,
}
