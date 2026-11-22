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

package com.davils.krypt.spiffe.x509

import com.davils.krypt.spiffe.SpiffeId
import com.davils.krypt.spiffe.internal.CheckedX509Svid
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.path.TrustAnchor

/**
 * An X.509-SVID that [X509SvidValidator] validated: its SPIFFE id, the validated path and the X.509 authority it leads
 * to.
 *
 * @property id the SPIFFE id of the leaf.
 * @param path the validated path, the leaf first, the anchor not included.
 * @property anchor the X.509 authority of the bundle of the trust domain of [id] the path leads to.
 * @since 1.0.0
 */
public class ValidatedX509Svid private constructor(
    public val id: SpiffeId,
    path: List<Certificate>,
    public val anchor: TrustAnchor,
) {
    /**
     * The validated path, the leaf first, the anchor not included.
     *
     * @since 1.0.0
     */
    public val path: List<Certificate> = path.toList()

    /**
     * The leaf.
     *
     * @since 1.0.0
     */
    public val certificate: Certificate get() = path.first()

    internal constructor(checked: CheckedX509Svid) :
        this(id = checked.id, path = checked.path, anchor = checked.anchor)

    /**
     * Compares the id, the path and the anchor.
     *
     * @param other the other object.
     * @return true if [other] is the same result.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is ValidatedX509Svid && id == other.id && path == other.path && anchor == other.anchor

    /**
     * Hashes the id, the path and the anchor.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = listOf(id, path, anchor).hashCode()

    /**
     * Shows the id, the length of the path and the anchor.
     *
     * @return the result as text.
     * @since 1.0.0
     */
    override fun toString(): String = "ValidatedX509Svid($id, ${path.size} certificates to $anchor)"
}
