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

package com.davils.krypt.cms.fixture

import com.davils.krypt.cms.enveloped.Credential
import com.davils.krypt.primitive.key.KeyPair
import com.davils.krypt.primitive.signature.Signer
import com.davils.krypt.x509.Certificate

internal class Identity(val pair: KeyPair, val certificate: Certificate) {
    val signer: Signer get() = crypto.signatures.signer(pair.privateKey)

    val credential: Credential get() = Credential.Certified(certificate, pair.privateKey)
}
