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

import com.davils.krypt.core.algorithm.MacAlgorithm
import com.davils.krypt.keyset.internal.Bytes
import com.davils.krypt.keyset.internal.Prefix
import com.davils.krypt.keyset.internal.materialOf
import com.davils.krypt.keyset.internal.primaryOf
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.Verification
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

/**
 * Message authentication with the keys of a [Keyset]: it computes tags with the primary key and verifies them with
 * whichever enabled key the tag names.
 *
 * A tag is a version byte, the eight bytes of the key id and the MAC. The same data and key always give the same tag,
 * so [computeAll] serves an index that must find data during a rotation.
 *
 * The object is safe to share between threads.
 *
 * @property keyset the key set.
 * @property algorithm the MAC of the key set.
 * @since 1.0.0
 */
public class KeysetMac internal constructor(
    private val crypto: Crypto,
    public val keyset: Keyset,
    public val algorithm: MacAlgorithm,
) {
    private val secrets: List<Pair<KeyId, SecretKey>> = keyset.usable { key -> key.secret }

    init {
        val purpose = keyset.purpose
        require(purpose is KeyPurpose.Mac && purpose.algorithm == algorithm) {
            "A key set of $purpose does not authenticate with $algorithm"
        }
    }

    /**
     * Computes the tag of [data] with the primary key.
     *
     * @param data the data.
     * @return the tag.
     * @since 1.0.0
     */
    public suspend fun compute(data: ByteString): ByteString =
        tagWith(id = keyset.primaryId, secret = secrets.primaryOf(keyset.primaryId), data = data)

    /**
     * Computes the tags of [data] with every enabled key, primary first.
     *
     * @param data the data.
     * @return the tags.
     * @since 1.0.0
     */
    public suspend fun computeAll(data: ByteString): List<ByteString> {
        val others = secrets.filter { (id, _) -> id != keyset.primaryId }
        return listOf(compute(data)) + others.map { (id, secret) -> tagWith(id = id, secret = secret, data = data) }
    }

    /**
     * Verifies [tag] of [data] in constant time.
     *
     * @param data the data.
     * @param tag the tag, possibly from an attacker.
     * @return [Verification.Valid] if an enabled key of the key set computed [tag] for [data].
     * @since 1.0.0
     */
    public suspend fun verify(data: ByteString, tag: ByteString): Verification {
        val parsed = Prefix.parseOrNull(tag)
        val secret = parsed?.let { found -> secrets.materialOf(found.id) } ?: return Verification.Invalid
        return crypto.macs.verify(key = secret, data = data, tag = parsed.rest, algorithm = algorithm)
    }

    /**
     * Shows the key set.
     *
     * @return the authentication as text.
     * @since 1.0.0
     */
    override fun toString(): String = "KeysetMac($keyset)"

    private suspend fun tagWith(id: KeyId, secret: SecretKey, data: ByteString): ByteString {
        val mac = crypto.macs.mac(key = secret, data = data, algorithm = algorithm)
        return Bytes.concat(Prefix.of(id), mac)
    }
}
