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

package com.davils.krypt.keystore.material

import com.davils.krypt.core.SecretText
import com.davils.krypt.keystore.Identity
import com.davils.krypt.keystore.pkcs12.KeyEntry
import com.davils.krypt.keystore.pkcs12.Pkcs12
import com.davils.krypt.keystore.pkcs12.Pkcs12Store
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.encodeToByteString

/**
 * Writes identities to a [MaterialSink].
 *
 * The private key is always marked as secret, so the sink restricts access before it writes. Exceptions of the sink
 * are not caught.
 *
 * @property crypto the primitives.
 * @property sink where the material goes.
 * @constructor Writes to [sink] with [crypto].
 * @since 1.0.0
 */
public class MaterialWriter(public val crypto: Crypto, public val sink: MaterialSink) {
    /**
     * Writes [identity] as a PKCS #12 file, as [Pkcs12.encode] does.
     *
     * @param ref where the file goes.
     * @param identity the identity.
     * @param password the password, which may not be empty.
     * @param alias the friendly name of the key, or null.
     * @param iterations the iterations of PBKDF2; the minimum of the crypto policy by default.
     * @throws IllegalArgumentException if [password] is empty.
     * @throws IllegalStateException if the private key is not extractable or was destroyed.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [iterations].
     * @since 1.0.0
     */
    public suspend fun writePkcs12(
        ref: MaterialRef,
        identity: Identity,
        password: SecretText,
        alias: String? = null,
        iterations: Int = crypto.environment.policy.minimumIterations,
    ) {
        val store = Pkcs12Store(keys = listOf(KeyEntry(identity = identity, alias = alias)))
        val bytes = Pkcs12(crypto).encode(store = store, password = password, iterations = iterations)
        sink.write(ref = ref, bytes = bytes, isSecret = true)
    }

    /**
     * Writes [identity] as PEM: the chain to [certificates] and the private key to [key], in encrypted PKCS #8 when
     * a password is given.
     *
     * Without a password, the key passes through a `String`, which cannot be wiped; prefer a password, or a sink
     * that encrypts.
     *
     * @param certificates where the chain goes.
     * @param key where the private key goes; it must differ from [certificates].
     * @param identity the identity.
     * @param password the password of the key, or null for an unencrypted key.
     * @param iterations the iterations of PBKDF2; the minimum of the crypto policy by default.
     * @throws IllegalArgumentException if [key] equals [certificates].
     * @throws IllegalStateException if the private key is not extractable or was destroyed.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [iterations].
     * @since 1.0.0
     */
    public suspend fun writePem(
        certificates: MaterialRef,
        key: MaterialRef,
        identity: Identity,
        password: SecretText? = null,
        iterations: Int = crypto.environment.policy.minimumIterations,
    ) {
        require(key != certificates) { "The key and the chain go to different references" }
        val codec = Certificates(crypto)
        val chain = identity.chain.joinToString(separator = "") { certificate -> codec.encodePem(certificate) }
        val encrypted = password?.let { secret ->
            crypto.keys.encryptPem(key = identity.privateKey, password = secret, iterations = iterations)
        }
        val keyText = encrypted ?: crypto.keys.encodePem(identity.privateKey)
        sink.write(ref = key, bytes = keyText.encodeToByteString(), isSecret = true)
        sink.write(ref = certificates, bytes = chain.encodeToByteString(), isSecret = false)
    }

    /**
     * Shows the sink.
     *
     * @return the writer as text.
     * @since 1.0.0
     */
    override fun toString(): String = "MaterialWriter($sink)"
}
