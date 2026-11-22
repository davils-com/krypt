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

import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.x509.Certificates
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

private const val AUDIT_NOW: Long = 1_800_000_000L

class AuditJavaReachTest : FunSpec({
    test("Java cannot pair a private key with the certificate of another key") {
        val crypto = Crypto()
        val victim = crypto.keys.generate(KeyType.P256)
        val other = crypto.keys.generate(KeyType.P256)
        val certificate = Certificates(crypto).issue(crypto.signatures.signer(victim.privateKey)) {
            subject { commonName("victim") }
            publicKey = victim.publicKey
            notBefore = Instant.fromEpochSeconds(AUDIT_NOW)
            notAfter = Instant.fromEpochSeconds(AUDIT_NOW) + 1.days
        }
        val constructor = Identity::class.java.constructors.firstOrNull()
        val forged = constructor?.newInstance(other.privateKey, listOf(certificate)) as? Identity
        forged?.certificate?.publicKey shouldBe null
    }
})
