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

package com.davils.krypt.jose

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.jose.internal.JsonReader
import kotlinx.io.bytestring.ByteString

/**
 * The strict and bounded JSON parser of krypt-jose, for the protocols of krypt built on JSON, such as ACME.
 *
 * It reads the I-JSON subset of [JsonValue]: UTF-8 without a byte order mark, unique member names, integers only.
 * It is stateless and safe to share between threads.
 *
 * @since 1.0.0
 */
@DavilsInternal
public object StrictJson {
    /**
     * Reads one JSON value from [bytes].
     *
     * @param bytes the UTF-8 text.
     * @param limits the size, depth, member and string limits.
     * @return the value, [JoseFailure.LimitExceeded] past a limit or [JoseFailure.Malformed].
     * @since 1.0.0
     */
    public fun decode(bytes: ByteString, limits: JoseLimits = JoseLimits.Default): Outcome<JsonValue, JoseFailure> =
        JsonReader.read(bytes.toByteArray(), limits)

    /**
     * Reads one JSON object from [bytes].
     *
     * @param bytes the UTF-8 text.
     * @param limits the size, depth, member and string limits.
     * @return the object, [JoseFailure.LimitExceeded] past a limit or [JoseFailure.Malformed], also if the value
     *   is no object.
     * @since 1.0.0
     */
    public fun decodeObject(
        bytes: ByteString,
        limits: JoseLimits = JoseLimits.Default,
    ): Outcome<JsonValue.Object, JoseFailure> = JsonReader.readObject(bytes.toByteArray(), limits)
}
