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

package com.davils.krypt.keyset

import com.davils.krypt.core.algorithm.AeadAlgorithm
import com.davils.krypt.keyset.fixture.keysets
import com.davils.krypt.keyset.store.StoredKeyset
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

private const val LATER: Long = 5L

class EqualityTest : FunSpec({
    test("values differ from other types") {
        val keyset = keysets.generate(KeyPurpose.Aead())
        val values: List<Any> = listOf(
            KeyPurpose.Aead(),
            KeyPurpose.Mac(),
            KeyPurpose.Signing(),
            KeyPurpose.Hybrid(),
            KeysetLimits(),
            keyset.primaryId,
            keyset,
            keyset.primary,
            StoredKeyset(revision = 1L, encrypted = ByteString()),
            KeysetEvent(action = KeysetAction.Added, keyId = keyset.primaryId),
        )
        values.forEach { value ->
            values.filter { other -> other !== value }.forEach { other -> value shouldNotBe other }
        }
    }

    test("a key set and its keys differ in every property") {
        val keyset = keysets.rotate(keysets.generate(KeyPurpose.Signing()))
        val key = keyset.primary
        val other = keyset.keys.first()
        val changed = listOf(
            KeysetKey(
                id = other.id,
                status = key.status,
                createdAt = key.createdAt,
                secret = null,
                privateKey = null,
                publicKey = key.publicKey,
            ),
            key.withStatus(KeyStatus.Disabled),
            KeysetKey(
                id = key.id,
                status = key.status,
                createdAt = Instant.fromEpochMilliseconds(LATER),
                secret = null,
                privateKey = null,
                publicKey = key.publicKey,
            ),
            key.publicOnly().let { public ->
                KeysetKey(
                    id = public.id,
                    status = public.status,
                    createdAt = public.createdAt,
                    secret = null,
                    privateKey = null,
                    publicKey = other.publicKey,
                )
            },
        )
        changed.forEach { variant -> variant shouldNotBe key }
        key.publicOnly() shouldBe key
        key.hashCode() shouldBe key.id.hashCode()
        Keyset(purpose = KeyPurpose.Signing(), keys = keyset.keys, primaryId = other.id) shouldNotBe keyset
        val aead = keysets.generate(KeyPurpose.Aead())
        val chacha = KeyPurpose.Aead(AeadAlgorithm.ChaCha20Poly1305)
        Keyset(purpose = chacha, keys = aead.keys, primaryId = aead.primaryId) shouldNotBe aead
        val symmetric = aead.primary
        val resecret = KeysetKey(
            id = symmetric.id,
            status = symmetric.status,
            createdAt = symmetric.createdAt,
            secret = keysets.crypto.keys.generateSecret(),
            privateKey = null,
            publicKey = null,
        )
        resecret shouldNotBe symmetric
        Keyset(purpose = keyset.purpose, keys = listOf(key), primaryId = keyset.primaryId) shouldNotBe keyset
        KeysetEvent(action = KeysetAction.Added, keyId = key.id) shouldNotBe
            KeysetEvent(action = KeysetAction.Added, keyId = other.id)
    }

    test("only enabled keys hand out their material") {
        val keyset = keysets.publicKeyset(keysets.rotate(keysets.generate(KeyPurpose.Signing())))
        keyset.usable { key -> key.privateKey } shouldBe emptyList()
        keyset.usable { key -> key.publicKey }.size shouldBe 2
    }
})
