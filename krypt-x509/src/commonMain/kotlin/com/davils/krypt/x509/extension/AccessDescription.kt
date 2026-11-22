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

package com.davils.krypt.x509.extension

import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.name.GeneralName

/**
 * One access description of the information access extensions, such as the URI of an OCSP responder.
 *
 * @property method the access method, such as [KeyPurposes.OcspAccess].
 * @property location where to find it.
 * @constructor Describes an access.
 * @since 1.0.0
 */
public class AccessDescription(public val method: ObjectIdentifier, public val location: GeneralName) {
    /**
     * Compares both properties.
     *
     * @param other the other object.
     * @return true if [other] is the same description.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is AccessDescription && method == other.method && location == other.location

    /**
     * Hashes both properties.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(method, location).hashCode()

    /**
     * Shows both properties.
     *
     * @return the description as text.
     * @since 1.0.0
     */
    override fun toString(): String = "AccessDescription(${method.dotted}, $location)"
}
