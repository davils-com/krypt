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

@file:OptIn(DavilsInternal::class, ExperimentalAtomicApi::class)

package com.davils.krypt.acme.internal

import com.davils.kontinuity.retry.Retry
import com.davils.kore.core.annotation.DavilsInternal
import com.davils.kore.core.failure.attempted
import com.davils.kore.core.outcome.Outcome
import com.davils.kore.core.outcome.failureOrNull
import com.davils.kore.core.outcome.flatMap
import com.davils.kore.core.outcome.getOrNull
import com.davils.kore.core.outcome.onSuccess
import com.davils.krypt.acme.AcmeDirectory
import com.davils.krypt.acme.AcmeError
import com.davils.krypt.acme.AcmeFailure
import com.davils.krypt.acme.AcmeLimits
import com.davils.krypt.acme.AcmeMethod
import com.davils.krypt.acme.AcmeProblem
import com.davils.krypt.acme.AcmeProblemType
import com.davils.krypt.acme.AcmeRequest
import com.davils.krypt.acme.AcmeResponse
import com.davils.krypt.acme.AcmeTransport
import com.davils.krypt.jose.JoseFailure
import com.davils.krypt.jose.JoseKey
import com.davils.krypt.jose.JoseLimits
import com.davils.krypt.jose.JsonValue
import com.davils.krypt.jose.StrictJson
import com.davils.krypt.jose.jwk.JsonWebKeys
import com.davils.krypt.jose.jws.Jws
import com.davils.krypt.jose.jws.JwsSigner
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.x509.Certificates
import kotlinx.io.bytestring.ByteString
import kotlinx.io.bytestring.encodeToByteString
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

internal class Exchange(
    private val transport: AcmeTransport,
    private val directoryUrl: String,
    val crypto: Crypto,
    val limits: AcmeLimits,
    private val retry: Retry?,
) {
    val keys: JsonWebKeys = JsonWebKeys(crypto)
    val readers: Readers = Readers(
        limits = limits,
        isHttpAllowed = transport.isPlainHttpAllowed,
        certificates = Certificates(crypto),
    )
    private val jws = Jws(crypto)
    private val nonces = NoncePool(limits.maximumNonces)
    private val cache = AtomicReference<AcmeDirectory?>(null)

    suspend fun directory(): Outcome<AcmeDirectory, AcmeFailure> {
        val cached = cache.load()
        if (cached != null) return Outcome.Success(cached)
        val read = get(directoryUrl).flatMap { reply -> json(reply) { json -> readers.directory(json) } }
        return read.onSuccess { directory -> cache.store(directory) }
    }

    suspend fun get(url: String): Outcome<Reply, AcmeFailure> {
        val sent = send(AcmeRequest(method = AcmeMethod.Get, url = url))
        return sent.flatMap { reply -> expect(reply = reply, statuses = OK) }
    }

    suspend fun post(
        url: String,
        payload: ByteString,
        signing: Signing,
        statuses: Set<Int> = OK,
        accept: String? = null,
    ): Outcome<Reply, AcmeFailure> = attempt(
        url = url,
        payload = payload,
        signing = signing,
        statuses = statuses,
        accept = accept,
        retries = limits.maximumNonceRetries,
    )

    suspend fun signed(payload: ByteString, url: String, nonce: String?, signing: Signing): JsonValue.Object {
        val identity = when (signing) {
            is Signing.ByKeyId -> KEY_ID to text(signing.accountUrl)
            is Signing.ByKey -> JWK to jwkOf(signing.key.publicKey)
        }
        val members = listOfNotNull(identity, nonce?.let { found -> NONCE to text(found) }, URL to text(url))
        val signer = JwsSigner(
            key = JoseKey.Private(signing.key.privateKey),
            algorithm = signing.key.algorithm,
            header = JsonValue.Object(members),
        )
        return flattened(jws.sign(payload = payload, signer = signer))
    }

    suspend fun signedWithMac(payload: ByteString, url: String, signer: JwsSigner): JsonValue.Object {
        val header = JsonValue.Object(signer.header.members + (URL to text(url)))
        val withUrl = JwsSigner(key = signer.key, algorithm = signer.algorithm, header = header)
        return flattened(jws.sign(payload = payload, signer = withUrl))
    }

    fun jwkOf(key: PublicKey): JsonValue.Object {
        val jwk = keys.of(key)
        val encoded = jwk.encode().encodeToByteString()
        return when (val read = StrictJson.decodeObject(bytes = encoded, limits = JoseLimits.Default)) {
            is Outcome.Success -> read.value
            is Outcome.Failure -> error("krypt-jose wrote a JWK it cannot read")
        }
    }

    fun <T> json(reply: Reply, block: (JsonValue.Object) -> T): Outcome<T, AcmeFailure> =
        reading { block(objectOf(reply.response.body)) }

    fun expect(reply: Reply, statuses: Set<Int>): Outcome<Reply, AcmeFailure> {
        if (reply.response.status in statuses) return Outcome.Success(reply)
        val problem = reading { readers.problem(json = objectOf(reply.response.body), retryAfter = reply.retryAfter) }
        return Outcome.Failure(problem.getOrNull() ?: AcmeError.UnexpectedStatus)
    }

    suspend fun send(request: AcmeRequest, isPooled: Boolean = true): Outcome<Reply, AcmeFailure> {
        val exchanged = attempted { exchanged(request) }
        val response = exchanged.getOrNull() ?: return Outcome.Failure(AcmeError.Transport)
        return reading { checked(response = response, isPooled = isPooled) }
    }

    private suspend fun exchanged(request: AcmeRequest): AcmeResponse {
        val active = retry ?: return transport.exchange(request)
        return active.execute { transport.exchange(request) }
    }

    private suspend fun attempt(
        url: String,
        payload: ByteString,
        signing: Signing,
        statuses: Set<Int>,
        accept: String?,
        retries: Int,
    ): Outcome<Reply, AcmeFailure> {
        val sent = nonce().flatMap { nonce ->
            val body = signed(payload = payload, url = url, nonce = nonce, signing = signing)
            send(postOf(url = url, body = body, accept = accept))
        }
        val outcome = sent.flatMap { reply -> expect(reply = reply, statuses = statuses) }
        val failure = outcome.failureOrNull()
        val isBadNonce = failure is AcmeProblem && failure.kind == AcmeProblemType.BadNonce
        if (isBadNonce && retries > 0) {
            return attempt(
                url = url,
                payload = payload,
                signing = signing,
                statuses = statuses,
                accept = accept,
                retries = retries - 1,
            )
        }
        return outcome
    }

    private suspend fun nonce(): Outcome<String, AcmeFailure> {
        val pooled = nonces.take()
        if (pooled != null) return Outcome.Success(pooled)
        val sent = directory().flatMap { directory ->
            send(request = AcmeRequest(method = AcmeMethod.Head, url = directory.newNonce), isPooled = false)
        }
        val reply = sent.flatMap { found -> expect(reply = found, statuses = NONCE_STATUSES) }
        return reply.flatMap { found -> reading { found.nonce ?: refuse(AcmeError.Malformed) } }
    }

    private fun postOf(url: String, body: JsonValue.Object, accept: String?): AcmeRequest {
        val headers = listOfNotNull(CONTENT_TYPE to JOSE_JSON, accept?.let { found -> ACCEPT to found })
        return AcmeRequest(
            method = AcmeMethod.Post,
            url = url,
            headers = headers,
            body = body.encode().encodeToByteString(),
        )
    }

    private suspend fun checked(response: AcmeResponse, isPooled: Boolean): Reply {
        val headers = response.headers
        val areHeadersSized = headers.size <= limits.maximumHeaders &&
            headers.all { (name, value) -> name.length + value.length <= limits.maximumHeaderBytes }
        val isSized = areHeadersSized && response.body.size <= limits.maximumResponseBytes
        refuseUnless(condition = isSized, error = AcmeError.LimitExceeded)
        val nonce = single(response.headers(REPLAY_NONCE))
        refuseUnless(nonce == null || Tokens.isNonce(nonce))
        val now = crypto.environment.clock.now()
        val retryAfter = single(response.headers(RETRY_AFTER))?.let { value ->
            HttpDates.retryAfter(value = value, now = now, maximum = limits.maximumRetryAfter)
        }
        val location = single(response.headers(LOCATION))?.let { value -> readers.url(value) }
        val links = Links.parse(values = response.headers(LINK), maximum = limits.maximumEntries)
        if (isPooled && nonce != null) nonces.offer(nonce)
        return Reply(response = response, retryAfter = retryAfter, location = location, links = links, nonce = nonce)
    }

    private fun objectOf(body: ByteString): JsonValue.Object =
        when (val read = StrictJson.decodeObject(bytes = body, limits = limits.json)) {
            is Outcome.Success -> read.value
            is Outcome.Failure -> refuse(errorOf(read.failure))
        }

    private fun errorOf(failure: JoseFailure): AcmeError = when (failure == JoseFailure.LimitExceeded) {
        true -> AcmeError.LimitExceeded
        false -> AcmeError.Malformed
    }

    private fun single(values: List<String>): String? {
        refuseUnless(values.size <= 1)
        return values.firstOrNull()
    }

    private fun flattened(compact: String): JsonValue.Object {
        val (protected, payload, signature) = compact.split('.')
        return JsonValue.Object.of(PROTECTED to text(protected), PAYLOAD to text(payload), SIGNATURE to text(signature))
    }

    companion object {
        const val OK_STATUS: Int = 200
        const val CREATED_STATUS: Int = 201
        val OK: Set<Int> = setOf(OK_STATUS)
        val CREATED: Set<Int> = setOf(CREATED_STATUS)
        val OK_OR_CREATED: Set<Int> = setOf(OK_STATUS, CREATED_STATUS)
        private val NONCE_STATUSES: Set<Int> = setOf(OK_STATUS, 204)
        private const val KEY_ID: String = "kid"
        private const val JWK: String = "jwk"
        private const val NONCE: String = "nonce"
        private const val URL: String = "url"
        private const val PROTECTED: String = "protected"
        private const val PAYLOAD: String = "payload"
        private const val SIGNATURE: String = "signature"
        private const val CONTENT_TYPE: String = "Content-Type"
        private const val ACCEPT: String = "Accept"
        private const val JOSE_JSON: String = "application/jose+json"
        private const val REPLAY_NONCE: String = "Replay-Nonce"
        private const val RETRY_AFTER: String = "Retry-After"
        private const val LOCATION: String = "Location"
        private const val LINK: String = "Link"
    }
}
