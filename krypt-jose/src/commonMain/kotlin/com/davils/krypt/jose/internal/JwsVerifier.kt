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

package com.davils.krypt.jose.internal

import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.flatMap
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.jws.JwsAlgorithm
import com.davils.krypt.jose.jws.JwsMessage
import com.davils.krypt.jose.jws.JwsSignature
import com.davils.krypt.jose.jws.VerifiedJws
import com.davils.krypt.primitive.CryptoException
import kotlinx.io.bytestring.ByteString

private const val DOT: Byte = '.'.code.toByte()

internal class JwsVerifier(private val signatures: JwsCrypto) {
    suspend fun verify(
        message: JwsMessage,
        algorithms: Set<JwsAlgorithm>,
        detached: ByteString?,
        critical: Set<String>,
        keysOf: KeySource,
    ): Outcome<VerifiedJws, JoseFailure> {
        if (message.payload != null && detached != null) return Outcome.Failure(JoseFailure.Malformed)
        val context = Context(
            algorithms = algorithms,
            payload = detached ?: message.payload ?: ByteString(),
            payloadInput = ByteString(payloadInputOf(message = message, detached = detached)),
            understood = critical + HeaderNames.BASE64,
            keysOf = keysOf,
        )
        return verifyAll(message, context)
    }

    private suspend fun verifyAll(message: JwsMessage, context: Context): Outcome<VerifiedJws, JoseFailure> {
        val failures = ArrayList<JoseFailure>()
        for (signature in message.signatures) {
            when (val outcome = attempt { verifyOne(signature, context) }) {
                is Outcome.Success -> return outcome
                is Outcome.Failure -> failures += outcome.failure
            }
        }
        return Outcome.Failure(failures.first())
    }

    private suspend fun verifyOne(signature: JwsSignature, context: Context): Outcome<VerifiedJws, JoseFailure> {
        val header = signature.header
        val algorithm = JwsAlgorithm.of(header.algorithm.orEmpty())
        val failure = HeaderRules.criticalFailure(
            protected = signature.protectedHeader,
            header = header.members,
            understood = context.understood,
        )
            ?: JoseFailure.UnsupportedAlgorithm.takeIf { algorithm == null }
            ?: JoseFailure.AlgorithmNotAllowed.takeUnless { algorithm in context.algorithms }
        if (failure != null) return Outcome.Failure(failure)
        return context.keysOf(signature).flatMap { keys ->
            matching(signature = signature, algorithm = invariant(algorithm), keys = keys, context = context)
        }
    }

    private suspend fun matching(
        signature: JwsSignature,
        algorithm: JwsAlgorithm,
        keys: List<JoseKey>,
        context: Context,
    ): Outcome<VerifiedJws, JoseFailure> {
        val protected = signature.protectedEncoded.encodeToByteArray()
        val input = ByteString(protected + DOT + context.payloadInput.toByteArray())
        val keyId = signature.header.keyId
        var isFitted = false
        var verified: JoseKey? = null
        val names = setOf(algorithm.algorithmName)
        val fitting = keys.filter { key -> key.keyId == null || keyId == null || key.keyId == keyId }
        for (key in fitting.filter { key -> isUsable(key, VERIFYING, names) }) {
            if (verified == null) {
                val isVerified = signatures.verify(
                    algorithm = algorithm,
                    key = key,
                    input = input,
                    signature = signature.signature,
                )
                isFitted = isFitted || isVerified != null
                verified = key.takeIf { isVerified == true }
            }
        }
        val failure = when (isFitted) {
            true -> JoseFailure.BadSignature
            false -> JoseFailure.KeyNotFound
        }
        val success = verified?.let { found ->
            Outcome.Success(
                VerifiedJws(payload = context.payload, header = signature.header, algorithm = algorithm, key = found),
            )
        }
        return success ?: Outcome.Failure(failure)
    }

    private inline fun attempt(block: () -> Outcome<VerifiedJws, JoseFailure>): Outcome<VerifiedJws, JoseFailure> =
        try {
            block()
        } catch (ignored: CryptoException) {
            Outcome.Failure(JoseFailure.AlgorithmNotAllowed)
        }

    private fun payloadInputOf(message: JwsMessage, detached: ByteString?): ByteArray {
        val bytes = detached ?: return message.payloadPart.encodeToByteArray()
        return when (message.isPayloadEncoded) {
            true -> Base64Url.encode(bytes).encodeToByteArray()
            false -> bytes.toByteArray()
        }
    }

    private data class Context(
        val algorithms: Set<JwsAlgorithm>,
        val payload: ByteString,
        val payloadInput: ByteString,
        val understood: Set<String>,
        val keysOf: KeySource,
    )
}
