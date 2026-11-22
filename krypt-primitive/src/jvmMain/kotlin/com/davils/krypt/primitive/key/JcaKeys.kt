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

@file:JvmName("JcaKeyBridge")

package com.davils.krypt.primitive.key

import com.davils.krypt.primitive.internal.JcaKeys
import java.security.PrivateKey as JcaPrivateKey
import java.security.PublicKey as JcaPublicKey

/**
 * Wraps a key pair of the JCA, such as a key a PKCS #11 provider holds in a hardware security module, without
 * extracting the private key: if the provider refuses to encode it, the private key of the result is not extractable
 * and every operation runs through the provider the [com.davils.krypt.primitive.Crypto] was configured with.
 *
 * @receiver the keys of a crypto object whose environment names the provider of [privateKey].
 * @param publicKey the public key, which must encode as a SubjectPublicKeyInfo.
 * @param privateKey the private key, extractable or not.
 * @return the key pair.
 * @throws IllegalArgumentException if the public key is not one krypt reads.
 * @since 1.0.0
 */
public fun Keys.fromJca(publicKey: JcaPublicKey, privateKey: JcaPrivateKey): KeyPair =
    JcaKeys.pairOf(publicKey = publicKey, privateKey = privateKey)
