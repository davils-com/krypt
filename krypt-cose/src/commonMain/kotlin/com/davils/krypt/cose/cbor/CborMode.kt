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

/**
 * How strictly a decoder reads CBOR.
 *
 * Both modes refuse what is not well formed, indefinite lengths, duplicate map keys, invalid UTF-8 and everything
 * beyond the [CborLimits].
 *
 * @since 1.0.0
 */
public enum class CborMode {
    /**
     * Accepts only the deterministic encoding of RFC 8949 section 4.2.1: shortest arguments, preferred floats and map
     * keys sorted by their bytes. The default.
     *
     * @since 1.0.0
     */
    Deterministic,

    /**
     * Accepts longer arguments, longer floats and map keys in any order as well, as some encoders of COSE write them.
     * Signatures and MACs still cover the bytes as they were received.
     *
     * @since 1.0.0
     */
    Relaxed,
}
