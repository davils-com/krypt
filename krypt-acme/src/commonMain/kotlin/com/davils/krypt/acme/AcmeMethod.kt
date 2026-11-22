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

package com.davils.krypt.acme

/**
 * The HTTP methods ACME uses.
 *
 * @property methodName the name of the method in HTTP.
 * @since 1.0.0
 */
public enum class AcmeMethod(public val methodName: String) {
    /**
     * `GET`, for the directory and the renewal information.
     *
     * @since 1.0.0
     */
    Get("GET"),

    /**
     * `HEAD`, for a fresh nonce.
     *
     * @since 1.0.0
     */
    Head("HEAD"),

    /**
     * `POST`, for every signed request.
     *
     * @since 1.0.0
     */
    Post("POST"),
}
