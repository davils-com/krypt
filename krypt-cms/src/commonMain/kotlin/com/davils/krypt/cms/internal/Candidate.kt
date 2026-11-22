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

package com.davils.krypt.cms.internal

import com.davils.krypt.cms.enveloped.Credential
import kotlinx.io.bytestring.ByteString

internal sealed interface Candidate {
    sealed interface Usable : Candidate

    data class Transport(val recipient: ParsedRecipient.Transport, val credential: Credential.Certified) : Usable

    data class Agreement(
        val recipient: ParsedRecipient.Agreement,
        val credential: Credential.Certified,
        val encryptedKey: ByteString,
    ) : Usable

    data class Kem(val recipient: ParsedRecipient.Kem, val credential: Credential.Certified) : Usable

    data class Kek(val recipient: ParsedRecipient.Kek, val credential: Credential.Kek) : Usable

    data class Password(val recipient: ParsedRecipient.Password, val credential: Credential.Password) : Usable

    data object Unsupported : Candidate
}
