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

package com.davils.krypt.asn1

/**
 * The class of an ASN.1 tag of X.680.
 *
 * @property bits the two high bits of the identifier octet, shifted down.
 * @since 1.0.0
 */
public enum class TagClass(public val bits: Int) {
    /**
     * The universal class, whose tags X.680 assigns, such as SEQUENCE or INTEGER.
     *
     * @since 1.0.0
     */
    Universal(bits = 0),

    /**
     * The application class.
     *
     * @since 1.0.0
     */
    Application(bits = 1),

    /**
     * The context-specific class, such as `[0]` in a certificate.
     *
     * @since 1.0.0
     */
    ContextSpecific(bits = 2),

    /**
     * The private class.
     *
     * @since 1.0.0
     */
    Private(bits = 3),
}
