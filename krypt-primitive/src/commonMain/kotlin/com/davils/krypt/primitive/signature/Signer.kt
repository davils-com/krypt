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

import com.davils.krypt.core.algorithm.SignatureAlgorithm
import com.davils.krypt.primitive.key.PublicKey
import kotlinx.io.bytestring.ByteString

/**
 * Something that signs with a private key, wherever the key lives: in memory, in a hardware security module or in a
 * key management service the caller reaches through its own client.
 *
 * Certificate authorities, JWS, COSE and CMS sign through a signer, so their keys never have to leave the device that
 * holds them. A signer produces ECDSA signatures in [SignatureFormat.Der]; callers that need the raw form convert.
 *
 * @since 1.0.0
 */
public interface Signer {
    /**
     * The algorithm the signer uses.
     *
     * @since 1.0.0
     */
    public val algorithm: SignatureAlgorithm

    /**
     * The public key that verifies the signatures.
     *
     * @since 1.0.0
     */
    public val publicKey: PublicKey

    /**
     * Signs [data].
     *
     * @param data the message.
     * @return the signature.
     * @since 1.0.0
     */
    public suspend fun sign(data: ByteString): ByteString
}
