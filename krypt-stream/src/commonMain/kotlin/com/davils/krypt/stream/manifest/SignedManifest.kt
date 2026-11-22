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

package com.davils.krypt.stream.manifest

/**
 * A [manifest] with the [signatures] of one or more signers and their countersignatures.
 *
 * @property manifest the manifest.
 * @since 1.0.0
 */
public class SignedManifest internal constructor(public val manifest: Manifest, signatures: List<ManifestSignature>) {
    /**
     * The signatures, in the order they were added.
     *
     * @since 1.0.0
     */
    public val signatures: List<ManifestSignature> = signatures.toList()

    /**
     * Compares the manifest and the signatures.
     *
     * @param other the other object.
     * @return true if [other] is the same signed manifest.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean =
        other is SignedManifest && manifest == other.manifest && signatures == other.signatures

    /**
     * Hashes the manifest.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = manifest.hashCode()

    /**
     * Shows the manifest and the number of signatures.
     *
     * @return the signed manifest as text.
     * @since 1.0.0
     */
    override fun toString(): String = "SignedManifest($manifest, signatures=${signatures.size})"
}
