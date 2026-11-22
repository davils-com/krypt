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

@file:OptIn(DavilsInternal::class)

package com.davils.krypt.primitive.key

import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.text.SafeText
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.EllipticCurve
import com.davils.krypt.core.algorithm.KeyFamily

/**
 * A private key: its family, its curve or size, the public key that belongs to it when it is known, and either its
 * PKCS #8 encoding or a handle of the platform, such as a key of a hardware security module that never leaves it.
 *
 * The encoding lives in [SecretBytes] and is wiped by [destroy]; a key of the platform forgets its handle. A destroyed
 * key refuses every operation. A private key is safe to use from several threads, but [destroy] must not race with an
 * operation.
 *
 * @property family the family of the key.
 * @property curve the curve of an elliptic curve key, or null.
 * @property bits the size of the key.
 * @property publicKey the public key that belongs to this key, or null if the encoding did not carry it.
 * @since 1.0.0
 */
public class PrivateKey internal constructor(
    public val family: KeyFamily,
    public val curve: EllipticCurve?,
    public val bits: Int,
    public val publicKey: PublicKey?,
    private val pkcs8: SecretBytes?,
    platformHandle: Any?,
) {
    internal var handle: Any? = platformHandle

    /**
     * Tells whether the key can be exported as PKCS #8; false for a key that lives in the platform, such as a key of
     * a hardware security module or a non-extractable key of WebCrypto.
     *
     * @since 1.0.0
     */
    public val isExtractable: Boolean = pkcs8 != null

    /**
     * Tells whether [destroy] was called.
     *
     * @since 1.0.0
     */
    public var isDestroyed: Boolean = false
        private set

    internal fun encodingOrNull(): SecretBytes? = pkcs8?.takeUnless { isDestroyed }

    internal fun withPublic(key: PublicKey): PrivateKey = PrivateKey(
        family = family,
        curve = curve,
        bits = bits,
        publicKey = key,
        pkcs8 = encodingOrNull()?.copy(),
        platformHandle = handle,
    )

    internal fun checkAlive() {
        check(!isDestroyed) { "The private key was destroyed, so it cannot be used any more" }
    }

    /**
     * Wipes the encoding and forgets the platform handle. Destroying twice does nothing.
     *
     * @since 1.0.0
     */
    public fun destroy() {
        pkcs8?.destroy()
        handle = null
        isDestroyed = true
    }

    /**
     * Compares by identity: two private keys are equal only if they are the same object, so no comparison ever
     * touches the secret.
     *
     * @param other the other object.
     * @return true if [other] is this key.
     * @since 1.0.0
     */
    override fun equals(other: Any?): Boolean = this === other

    /**
     * Returns the identity hash.
     *
     * @return the hash.
     * @since 1.0.0
     */
    override fun hashCode(): Int = super.hashCode()

    /**
     * Shows the family, the curve and the size, never the key.
     *
     * @return the key as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "PrivateKey($family, curve=${curve?.curveName.orEmpty()}, bits=$bits, key=${SafeText.REDACTED}, " +
            "extractable=$isExtractable, destroyed=$isDestroyed)"
}
