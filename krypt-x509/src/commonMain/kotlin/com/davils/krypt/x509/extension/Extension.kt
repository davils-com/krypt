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
import kotlinx.io.bytestring.ByteString

/**
 * One extension as it is encoded: its identifier, whether it is critical and its DER value.
 *
 * @property id the identifier.
 * @property isCritical whether a reader that does not know it must refuse the structure.
 * @property value the DER encoding of the value.
 * @constructor Holds an extension.
 * @since 1.0.0
 */
public class Extension(public val id: ObjectIdentifier, public val isCritical: Boolean, public val value: ByteString) {
    /**
     * Compares every property.
     *
     * @param other the other object.
     * @return true if [other] is the same extension.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is Extension && id == other.id && isCritical == other.isCritical && value == other.value

    /**
     * Hashes the identifier.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = id.hashCode()

    /**
     * Shows the identifier and whether it is critical.
     *
     * @return the extension as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Extension(${id.dotted}, critical=$isCritical)"
}
