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

package com.davils.krypt.cms.signed

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.cms.ContentTypes
import com.davils.krypt.cms.internal.SignerSpec
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate
import com.davils.krypt.x509.crl.RevocationList

/**
 * Describes signed data: its content type, whether the content is detached, the signers and what else travels with
 * the message.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class SignedDataBuilder internal constructor() {
    internal val signers: MutableList<SignerSpec> = mutableListOf()

    internal val certificates: MutableList<Certificate> = mutableListOf()

    internal val revocationLists: MutableList<RevocationList> = mutableListOf()

    /**
     * The type of the content; [ContentTypes.Data] by default.
     *
     * @since 1.0.0
     */
    public var contentType: ObjectIdentifier = ContentTypes.Data

    /**
     * True to leave the content out of the message, which then signs content that travels apart.
     *
     * @since 1.0.0
     */
    public var isDetached: Boolean = false

    /**
     * Adds a signer.
     *
     * @param signer the signer, possibly a key in an HSM; its algorithm decides the digest: the one of ECDSA and RSA,
     *   SHA-512 for Ed25519 and ML-DSA.
     * @param certificate the signer's certificate, whose public key is the one of [signer].
     * @param block the options of the signer.
     * @since 1.0.0
     */
    public fun signer(signer: Signer, certificate: Certificate, block: SignerBuilder.() -> Unit = {}) {
        val options = SignerBuilder()
        options.block()
        signers += SignerSpec(signer = signer, certificate = certificate, options = options)
    }

    /**
     * Adds certificates to carry in the message, such as the chains of the signers.
     *
     * @param certificates the certificates.
     * @since 1.0.0
     */
    public fun certificates(certificates: List<Certificate>) {
        this.certificates += certificates
    }

    /**
     * Adds revocation lists to carry in the message.
     *
     * @param lists the revocation lists.
     * @since 1.0.0
     */
    public fun revocationLists(lists: List<RevocationList>) {
        revocationLists += lists
    }
}
