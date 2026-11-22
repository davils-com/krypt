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

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.keystore.internal.Chains
import com.davils.krypt.keystore.internal.IdentityParts
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.x509.Certificate

/**
 * Forms [Identity]s from a private key and certificates.
 *
 * @property crypto the primitives that prove the pair.
 * @constructor Forms identities with [crypto].
 * @since 1.0.0
 */
public class Identities(public val crypto: Crypto) {
    /**
     * Finds the certificate of [privateKey] among [certificates] and orders its chain.
     *
     * The certificate is found by proving the pair, so a certificate of another key is never taken; the first
     * certificate that pairs wins. The chain then follows each issuer by name, and certificates that do not belong to
     * it are left out. The certificates are not validated: validate the chain with a
     * [com.davils.krypt.x509.path.PathValidator] where it matters.
     *
     * @param privateKey the private key.
     * @param certificates the certificates, in any order.
     * @return the identity, or why there is none.
     * @since 1.0.0
     */
    public suspend fun of(privateKey: PrivateKey, certificates: List<Certificate>): Outcome<Identity, IdentityFailure> {
        if (certificates.isEmpty()) return Outcome.Failure(IdentityFailure.NoCertificate)
        val leaf = certificates.firstOrNull { certificate -> isPaired(privateKey, certificate) }
        val identity = leaf?.let { found ->
            Identity(IdentityParts(privateKey = privateKey, chain = Chains.of(found, certificates)))
        }
        return identity?.let { formed -> Outcome.Success(formed) } ?: Outcome.Failure(IdentityFailure.KeyMismatch)
    }

    /**
     * Shows the primitives.
     *
     * @return the object as text.
     * @since 1.0.0
     */
    override fun toString(): String = "Identities($crypto)"

    private suspend fun isPaired(privateKey: PrivateKey, certificate: Certificate): Boolean {
        val publicKey = certificate.publicKey?.takeIf { key -> key.family == privateKey.family } ?: return false
        return crypto.keys.pair(privateKey = privateKey, publicKey = publicKey) != null
    }
}
