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

package com.davils.krypt.keyset.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.algorithm.KeyType
import com.davils.krypt.keyset.KeyId
import com.davils.krypt.keyset.KeyPurpose
import com.davils.krypt.keyset.KeyStatus
import com.davils.krypt.keyset.Keyset
import com.davils.krypt.keyset.KeysetFailure
import com.davils.krypt.keyset.KeysetKey
import com.davils.krypt.keyset.internal.Refusal.Companion.ensure
import com.davils.krypt.keyset.internal.Refusal.Companion.refuse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.KeyFailure
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString
import kotlin.time.Instant

internal class KeysetAssembly(private val crypto: Crypto, private val isPublic: Boolean) {
    suspend fun assemble(raw: RawKeyset): Keyset {
        ensure(raw.version == KeysetCodec.VERSION, KeysetFailure.Unsupported)
        val purpose = raw.purpose ?: refuse(KeysetFailure.Unsupported)
        ensure(raw.primary.size == KeyId.SIZE && raw.keys.isNotEmpty(), KeysetFailure.Malformed)
        val primaryId = KeyId.of(raw.primary)
        val keys = raw.keys.map { key -> keyOf(purpose, key) }
        val ids = keys.map { key -> key.id }
        ensure(ids.toSet().size == ids.size, KeysetFailure.Malformed)
        val primary = keys.firstOrNull { key -> key.id == primaryId }
        ensure(primary?.status == KeyStatus.Enabled, KeysetFailure.Malformed)
        return Keyset(purpose = purpose, keys = keys, primaryId = primaryId)
    }

    private suspend fun keyOf(purpose: KeyPurpose, raw: RawKey): KeysetKey {
        ensure(raw.id.size == KeyId.SIZE, KeysetFailure.Malformed)
        val status = KeyStatus.entries.getOrNull(raw.status) ?: refuse(KeysetFailure.Malformed)
        val base = KeysetKey(
            id = KeyId.of(raw.id),
            status = KeyStatus.Destroyed,
            createdAt = Instant.fromEpochMilliseconds(raw.createdAt),
            secret = null,
            privateKey = null,
            publicKey = null,
        )
        val hasNoMaterial = raw.secret == null && raw.privateKey == null && raw.publicKey == null
        return when (status == KeyStatus.Destroyed) {
            true -> base.also { ensure(hasNoMaterial, KeysetFailure.Malformed) }
            false -> materialOf(purpose = purpose, base = base, raw = raw, status = status)
        }
    }

    private suspend fun materialOf(purpose: KeyPurpose, base: KeysetKey, raw: RawKey, status: KeyStatus): KeysetKey {
        val type = purpose.keyType
            ?: return symmetric(base = base, raw = raw, size = purpose.secretBytes, status = status)
        return asymmetric(base = base, raw = raw, type = type, status = status)
    }

    private fun symmetric(base: KeysetKey, raw: RawKey, size: Int, status: KeyStatus): KeysetKey {
        val hasNoPair = raw.privateKey == null && raw.publicKey == null
        val secret = raw.secret?.takeIf { found -> !isPublic && found.size == size && hasNoPair }
            ?: refuse(KeysetFailure.Malformed)
        val key = SecretKey.of(SecretBytes.copyOf(secret))
        return KeysetKey(
            id = base.id,
            status = status,
            createdAt = base.createdAt,
            secret = key,
            privateKey = null,
            publicKey = null,
        )
    }

    private suspend fun asymmetric(base: KeysetKey, raw: RawKey, type: KeyType, status: KeyStatus): KeysetKey {
        val hasPrivate = raw.privateKey != null
        ensure(raw.secret == null && hasPrivate != isPublic, KeysetFailure.Malformed)
        val public = publicOf(raw.publicKey ?: refuse(KeysetFailure.Malformed), type)
        val private = raw.privateKey?.let { encoded -> privateOf(encoded = encoded, public = public, type = type) }
        return KeysetKey(
            id = base.id,
            status = status,
            createdAt = base.createdAt,
            secret = null,
            privateKey = private,
            publicKey = public,
        )
    }

    private fun publicOf(encoded: ByteString, type: KeyType): PublicKey {
        val key = valueOf(crypto.keys.decodePublic(encoded))
        val isMatching = KeyTypes.matches(type = type, family = key.family, bits = key.bits, curve = key.curve)
        ensure(isMatching, KeysetFailure.Malformed)
        return key
    }

    private suspend fun privateOf(encoded: ByteString, public: PublicKey, type: KeyType): PrivateKey {
        val key = valueOf(crypto.keys.decodePrivate(SecretBytes.copyOf(encoded)))
        val isMatching = KeyTypes.matches(type = type, family = key.family, bits = key.bits, curve = key.curve)
        ensure(isMatching, KeysetFailure.Malformed)
        val pair = crypto.keys.pair(privateKey = key, publicKey = public) ?: refuse(KeysetFailure.Malformed)
        return pair.privateKey
    }

    private fun <T> valueOf(outcome: Outcome<T, KeyFailure>): T = when (outcome) {
        is Outcome.Success -> outcome.value
        is Outcome.Failure -> refuse(FAILURES[outcome.failure] ?: KeysetFailure.Malformed)
    }

    private companion object {
        val FAILURES: Map<KeyFailure, KeysetFailure> = mapOf(
            KeyFailure.UnsupportedAlgorithm to KeysetFailure.Unsupported,
            KeyFailure.Refused to KeysetFailure.Refused,
        )
    }
}
