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

package com.davils.krypt.primitive.password

/**
 * The result of checking a password against a stored hash.
 *
 * @since 1.0.0
 */
public enum class PasswordVerification {
    /**
     * The password is right, and the hash is as strong as the policy demands.
     *
     * @since 1.0.0
     */
    Valid,

    /**
     * The password is right, but the hash is weaker than the policy demands for a new one, such as fewer iterations;
     * the caller should hash the password again and store the new hash.
     *
     * @since 1.0.0
     */
    ValidButOutdated,

    /**
     * The password is wrong.
     *
     * @since 1.0.0
     */
    Invalid,

    /**
     * The stored hash is not one krypt reads, or it demands more work than the policy permits.
     *
     * @since 1.0.0
     */
    Malformed,
    ;

    /**
     * Tells whether the password is right.
     *
     * @since 1.0.0
     */
    public val isValid: Boolean get() = this == Valid || this == ValidButOutdated
}
