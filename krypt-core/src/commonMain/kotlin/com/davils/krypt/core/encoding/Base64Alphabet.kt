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

package com.davils.krypt.core.encoding

/**
 * The alphabet of a [Base64] text.
 *
 * @since 1.0.0
 */
public enum class Base64Alphabet {
    /**
     * The alphabet of RFC 4648 section 4, with `+` and `/`, as in PEM, PKCS #12 passwords and MIME.
     *
     * @since 1.0.0
     */
    Standard,

    /**
     * The URL and file name safe alphabet of RFC 4648 section 5, with `-` and `_`, as in JOSE and ACME.
     *
     * @since 1.0.0
     */
    Url,
}
