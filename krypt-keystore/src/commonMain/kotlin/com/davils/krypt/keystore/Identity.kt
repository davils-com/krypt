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

package com.davils.krypt.keystore

import com.davils.krypt.keystore.internal.IdentityParts
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.x509.Certificate

/**
 * An identity: a private key and the chain of its certificate, the end entity first, as a TLS server or client
 * presents it.
 *
 * An identity is only created by [Identities] after the private key was proven to belong to the first certificate.
 * It holds the private key: do not share it beyond what needs it, and destroy the key when it is no longer used.
 *
 * @property privateKey the private key.
 * @since 1.0.0
 */
public class Identity private constructor(public val privateKey: PrivateKey, chain: List<Certificate>) {
    /**
     * The chain, the certificate of the private key first, each followed by its issuer.
     *
     * @since 1.0.0
     */
    public val chain: List<Certificate> = chain.toList()

    /**
     * The certificate of the private key.
     *
     * @since 1.0.0
     */
    public val certificate: Certificate get() = chain.first()

    internal constructor(parts: IdentityParts) : this(parts.privateKey, parts.chain)

    /**
     * Compares the chains; the private key is proven to belong to the first certificate.
     *
     * @param other the other object.
     * @return true if [other] has the same chain.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = other is Identity && chain == other.chain

    /**
     * Hashes the chain.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = chain.hashCode()

    /**
     * Shows the subject and the length of the chain, never the key.
     *
     * @return the identity as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Identity(${certificate.subject}, chain=${chain.size})"
}
