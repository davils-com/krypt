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

package com.davils.krypt.primitive.password

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.ConstantTime
import com.davils.krypt.core.SecretText
import com.davils.krypt.core.algorithm.KdfAlgorithm
import com.davils.krypt.core.encoding.Base64
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import kotlinx.io.bytestring.ByteString

private const val SALT_BYTES: Int = 16
private const val HASH_BYTES: Int = 32
private const val MINIMUM_HASH: Int = 16
private const val MAXIMUM_HASH: Int = 64
private const val MAXIMUM_ENCODED: Int = 512
private const val FIELDS: Int = 5
private const val SEPARATOR: Char = '$'

/**
 * Hashes passwords for storage with PBKDF2, in the PHC string format: `$pbkdf2-sha256$i=600000,l=32$<salt>$<hash>`,
 * with salt and hash in unpadded Base64.
 *
 * New hashes use the iterations the policy demands for new protection; checking accepts what the policy verifies and
 * reports a hash below the current strength as [PasswordVerification.ValidButOutdated], so applications upgrade
 * hashes on the next successful login. A stored hash that demands more iterations than the policy permits is refused
 * unchecked, so a tampered database cannot stall the server.
 *
 * @since 1.0.0
 */
public class PasswordHasher internal constructor(private val crypto: Crypto) {
    /**
     * Hashes [password].
     *
     * @param password the password.
     * @param algorithm the PBKDF2; [KdfAlgorithm.Pbkdf2Sha256] by default.
     * @return the PHC string.
     * @throws IllegalArgumentException if [algorithm] is not a PBKDF2.
     * @throws com.davils.krypt.primitive.PolicyViolationException if the policy forbids [algorithm].
     * @since 1.0.0
     */
    public suspend fun hash(password: SecretText, algorithm: KdfAlgorithm = KdfAlgorithm.Pbkdf2Sha256): String {
        val iterations = crypto.environment.policy.minimumIterations
        val salt = ByteString(crypto.environment.random.bytes(SALT_BYTES))
        val derived = crypto.derivations.pbkdf2(
            password = password,
            salt = salt,
            iterations = iterations,
            length = HASH_BYTES,
            algorithm = algorithm,
        )
        val hash = derived.use { secret -> secret.reveal { bytes -> Base64.encode(bytes = bytes, padding = false) } }
        val salted = Base64.encode(bytes = salt, padding = false)
        return "$SEPARATOR${identifierOf(
            algorithm,
        )}${SEPARATOR}i=$iterations,l=$HASH_BYTES$SEPARATOR$salted$SEPARATOR$hash"
    }

    /**
     * Checks [password] against [encoded], in constant time.
     *
     * @param password the password.
     * @param encoded the stored PHC string.
     * @return whether the password is right and the hash is current.
     * @since 1.0.0
     */
    public suspend fun verify(password: SecretText, encoded: String): PasswordVerification {
        val policy = crypto.environment.policy
        val stored = parse(encoded)?.takeIf { found ->
            policy.permitsIterations(
                found.iterations,
                AlgorithmUse.Verify,
            ) &&
                policy.permits(found.algorithm, AlgorithmUse.Verify)
        }
        val found = stored ?: return PasswordVerification.Malformed
        return check(password = password, stored = found)
    }

    private suspend fun check(password: SecretText, stored: StoredHash): PasswordVerification {
        val derived = crypto.derivations.pbkdf2(
            password = password,
            salt = stored.salt,
            iterations = stored.iterations,
            length = stored.hash.size,
            algorithm = stored.algorithm,
            use = AlgorithmUse.Verify,
        )
        val expected = stored.hash.toByteArray()
        val isRight = derived.use { secret ->
            secret.reveal { bytes ->
                ConstantTime.equals(
                    first = bytes,
                    second = expected,
                )
            }
        }
        val policy = crypto.environment.policy
        val isStrongEnough = stored.iterations >= policy.minimumIterations
        val isCurrent = isStrongEnough && policy.permits(stored.algorithm, AlgorithmUse.Protect)
        val outcome = PasswordVerification.Invalid.takeUnless { isRight }
            ?: PasswordVerification.ValidButOutdated.takeUnless { isCurrent }
        return outcome ?: PasswordVerification.Valid
    }

    private fun parse(encoded: String): StoredHash? {
        val fields = encoded.takeIf { text -> text.length <= MAXIMUM_ENCODED }?.split(SEPARATOR)
        val parts = fields?.takeIf { found -> found.size == FIELDS && found[0].isEmpty() }
        return parts?.let { found -> storedOf(found) }
    }

    private fun storedOf(parts: List<String>): StoredHash? {
        val algorithm = ALGORITHMS[parts[1]]
        val parameters = parametersOf(parts[2])
        val iterations = parameters["i"]?.toIntOrNull()
        val length = parameters["l"]?.toIntOrNull()
        val salt = Base64.decode(text = parts[3], padding = false).getOrNull()
        val hash = Base64.decode(text = parts[4], padding = false).getOrNull()
        val isComplete = algorithm != null && iterations != null && salt != null && hash != null && parameters.size == 2
        val hashSize = hash?.size
        val isHashSized = hashSize == length && hashSize in MINIMUM_HASH..MAXIMUM_HASH
        val isConsistent = isHashSized && (salt?.size ?: 0) >= SALT_BYTES
        if (!isComplete || !isConsistent) return null
        return StoredHash(algorithm = algorithm, iterations = iterations, salt = salt, hash = hash)
    }

    private fun parametersOf(text: String): Map<String, String> {
        val pairs = text.split(',')
        return pairs.associate { pair ->
            pair.substringBefore(
                '=',
            ) to pair.substringAfter(delimiter = '=', missingDelimiterValue = "")
        }
    }

    private fun identifierOf(algorithm: KdfAlgorithm): String =
        ALGORITHMS.entries.firstOrNull { (_, candidate) -> candidate == algorithm }?.key
            ?: throw IllegalArgumentException("${algorithm.algorithmName} is not a password hash")

    private data class StoredHash(
        val algorithm: KdfAlgorithm,
        val iterations: Int,
        val salt: ByteString,
        val hash: ByteString,
    )

    private companion object {
        val ALGORITHMS: Map<String, KdfAlgorithm> = mapOf(
            "pbkdf2-sha256" to KdfAlgorithm.Pbkdf2Sha256,
            "pbkdf2-sha512" to KdfAlgorithm.Pbkdf2Sha512,
        )
    }
}
