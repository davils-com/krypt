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

package com.davils.krypt.primitive.signature

/**
 * How an ECDSA signature is encoded; other signatures have one encoding only and ignore the format.
 *
 * @since 1.0.0
 */
public enum class SignatureFormat {
    /**
     * The DER SEQUENCE of r and s, as X.509, CMS and TLS use it.
     *
     * @since 1.0.0
     */
    Der,

    /**
     * The concatenation of r and s, each as long as the field of the curve, as IEEE P1363, JOSE and COSE use it.
     *
     * @since 1.0.0
     */
    Raw,
}
