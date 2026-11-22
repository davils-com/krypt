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

package com.davils.krypt.primitive

/**
 * The result of checking a signature or a MAC.
 *
 * @since 1.0.0
 */
public enum class Verification {
    /**
     * The signature or the tag is valid for the data and the key.
     *
     * @since 1.0.0
     */
    Valid,

    /**
     * The signature or the tag is not valid, or not even well formed; krypt does not say which.
     *
     * @since 1.0.0
     */
    Invalid,
    ;

    /**
     * Tells whether this is [Valid].
     *
     * @since 1.0.0
     */
    public val isValid: Boolean get() = this == Valid

    /**
     * The factory of a verification.
     *
     * @since 1.0.0
     */
    public companion object {
        /**
         * Returns [Valid] if [isValid] is true, [Invalid] otherwise.
         *
         * @param isValid whether the check passed.
         * @return the verification.
         * @since 1.0.0
         */
        public fun of(isValid: Boolean): Verification = entries[1 - isValid.compareTo(false)]
    }
}
