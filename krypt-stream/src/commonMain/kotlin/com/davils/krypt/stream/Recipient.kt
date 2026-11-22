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

package com.davils.krypt.stream

import com.davils.krypt.core.SecretText
import com.davils.krypt.keyset.HybridEncrypter
import com.davils.krypt.keyset.KeysetAead
import com.davils.krypt.keyset.kms.KeyManagementService

private const val DEFAULT_ITERATIONS: Int = 600_000

/**
 * Someone who can open a container: the data key of the container is encrypted once for every recipient.
 *
 * @since 1.0.0
 */
public sealed interface Recipient {
    /**
     * The holder of a symmetric key set, such as the key encryption key of a service; it opens with
     * [Credential.Key] of the same key set, also after a rotation.
     *
     * @property aead the encryption of the key set.
     * @constructor Encrypts the data key with the primary key of [aead].
     * @since 1.0.0
     */
    public class Key(public val aead: KeysetAead) : Recipient {
        /**
         * Shows the key set.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Recipient.Key(${aead.keyset})"
    }

    /**
     * The holder of a private key set of HPKE, such as a person or a device; it opens with [Credential.Hybrid].
     *
     * @property encrypter the encryption to the public key set.
     * @constructor Encrypts the data key to the primary key of [encrypter].
     * @since 1.0.0
     */
    public class Hybrid(public val encrypter: HybridEncrypter) : Recipient {
        /**
         * Shows the key set.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Recipient.Hybrid(${encrypter.keyset})"
    }

    /**
     * A key management service, whose key URI is stored with the recipient; it opens with [Credential.Service] of
     * a service with the same key URI.
     *
     * @property kms the key management service.
     * @constructor Encrypts the data key with [kms].
     * @since 1.0.0
     */
    public class Service(public val kms: KeyManagementService) : Recipient {
        /**
         * Shows the service.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Recipient.Service(${kms.keyUri})"
    }

    /**
     * Whoever knows [password]: the data key is encrypted with a key derived by PBKDF2 with SHA-256 and a fresh salt.
     *
     * @property password the password; the caller keeps and wipes it.
     * @property iterations the iterations of PBKDF2; 600 000 by default.
     * @constructor Encrypts the data key with a key derived from [password].
     * @since 1.0.0
     */
    public class Password(
        public val password: SecretText,
        public val iterations: Int = DEFAULT_ITERATIONS,
    ) : Recipient {
        /**
         * Shows the iterations, never the password.
         *
         * @return the recipient as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Recipient.Password(iterations=$iterations)"
    }
}
