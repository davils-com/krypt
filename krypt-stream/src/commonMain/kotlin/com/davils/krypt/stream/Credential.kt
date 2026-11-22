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
import com.davils.krypt.keyset.HybridDecrypter
import com.davils.krypt.keyset.KeysetAead
import com.davils.krypt.keyset.kms.KeyManagementService

/**
 * What opens a container for one of its [Recipient]s.
 *
 * @since 1.0.0
 */
public sealed interface Credential {
    /**
     * The symmetric key set of a [Recipient.Key].
     *
     * @property aead the encryption of the key set.
     * @constructor Opens with [aead].
     * @since 1.0.0
     */
    public class Key(public val aead: KeysetAead) : Credential {
        /**
         * Shows the key set.
         *
         * @return the credential as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Credential.Key(${aead.keyset})"
    }

    /**
     * The private key set of a [Recipient.Hybrid].
     *
     * @property decrypter the decryption of the private key set.
     * @constructor Opens with [decrypter].
     * @since 1.0.0
     */
    public class Hybrid(public val decrypter: HybridDecrypter) : Credential {
        /**
         * Shows the key set.
         *
         * @return the credential as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Credential.Hybrid(${decrypter.keyset})"
    }

    /**
     * The key management service of a [Recipient.Service].
     *
     * It is asked at most once per container, for the first recipient that names its key. A service that throws is
     * contained and opens nothing; a cancellation of the caller passes on.
     *
     * @property kms the key management service.
     * @constructor Opens with [kms].
     * @since 1.0.0
     */
    public class Service(public val kms: KeyManagementService) : Credential {
        /**
         * Shows the service.
         *
         * @return the credential as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Credential.Service(${kms.keyUri})"
    }

    /**
     * The password of a [Recipient.Password]; the iterations it asks for are checked against the policy and the
     * limits before any work, and it costs at most one PBKDF2 per container, which holds at most one password
     * recipient.
     *
     * @property password the password; the caller keeps and wipes it.
     * @constructor Opens with [password].
     * @since 1.0.0
     */
    public class Password(public val password: SecretText) : Credential {
        /**
         * Shows nothing of the password.
         *
         * @return the credential as text.
         * @since 1.0.0
         */
        override fun toString(): String = "Credential.Password(****)"
    }
}
