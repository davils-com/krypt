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

package com.davils.krypt.cose.internal

import com.davils.krypt.core.ConstantTime
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseAlgorithmKind
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.CoseMac
import com.davils.krypt.cose.CoseMac0
import com.davils.krypt.cose.CoseRecipientSpec
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeyOperation
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

internal class Macing(
    private val crypto: Crypto,
    private val permissions: Permissions,
    private val recipients: Recipients,
    private val understood: List<CborItem>,
) {
    suspend fun mac0(payload: ByteString, key: CoseKey, algorithm: CoseAlgorithm, layer: Layer): CoseMac0 {
        require(algorithm.kind == CoseAlgorithmKind.Mac) { "${algorithm.algorithmName} is no MAC" }
        val operation = CoseKeyOperation.MacCreate
        val fitting = KeyFit.secretOf(key = key, algorithm = algorithm, operation = operation, bytes = null)
        val secret = requireNotNull(fitting) { "The key cannot MAC with ${algorithm.algorithmName}" }
        val buckets = layer.buckets(algorithm, key.keyId)
        val data = Structures.mac(
            context = Structures.MAC0,
            protectedEncoding = buckets.protectedEncoding,
            externalAad = layer.externalAad,
            payload = payload,
        )
        return CoseMac0(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            payload = payload.takeUnless { layer.isDetached },
            tag = tag(key = secret, algorithm = algorithm, data = data),
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    suspend fun mac(
        payload: ByteString,
        algorithm: CoseAlgorithm,
        specs: List<CoseRecipientSpec>,
        layer: Layer,
    ): CoseMac {
        require(algorithm.kind == CoseAlgorithmKind.Mac) { "${algorithm.algorithmName} is no MAC" }
        val buckets = layer.buckets(algorithm, null)
        val created = recipients.create(specs, algorithm)
        val data = Structures.mac(
            context = Structures.MAC,
            protectedEncoding = buckets.protectedEncoding,
            externalAad = layer.externalAad,
            payload = payload,
        )
        val key = created.contentKey.use { bytes -> SecretKey.of(bytes) }
        val tag = tag(key = key, algorithm = algorithm, data = data)
        key.destroy()
        return CoseMac(
            protectedHeaders = buckets.protectedHeaders,
            unprotectedHeaders = buckets.unprotectedHeaders,
            payload = payload.takeUnless { layer.isDetached },
            tag = tag,
            recipients = created.recipients,
            protectedEncoding = buckets.protectedEncoding,
        )
    }

    suspend fun verify(message: CoseMac0, request: Request): ByteString {
        val payload = Payloads.of(attached = message.payload, detached = request.detached)
        val algorithm = algorithmOf(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            request = request,
        )
        val keyId = Layers.keyIdOf(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
        )
        val secrets = request.keys.filter { key -> KeyFit.isKeyIdFit(key, keyId) }.mapNotNull { key ->
            KeyFit.secretOf(key = key, algorithm = algorithm, operation = CoseKeyOperation.MacVerify, bytes = null)
        }
        ensure(secrets.isNotEmpty(), CoseFailure.KeyNotFound)
        val data = Structures.mac(
            context = Structures.MAC0,
            protectedEncoding = message.protectedEncoding,
            externalAad = request.externalAad,
            payload = payload,
        )
        val isValid = secrets.any { secret ->
            isValid(key = secret, algorithm = algorithm, data = data, tag = message.tag)
        }
        ensure(isValid, CoseFailure.InvalidTag)
        return payload
    }

    suspend fun verify(message: CoseMac, request: Request): ByteString {
        val payload = Payloads.of(attached = message.payload, detached = request.detached)
        val algorithm = algorithmOf(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            request = request,
        )
        val candidates = recipients.candidates(
            recipients = message.recipients,
            keys = request.keys,
            allowed = request.algorithms,
            content = algorithm,
            operation = CoseKeyOperation.MacVerify,
        )
        ensure(candidates.isPermitted, CoseFailure.AlgorithmNotPermitted)
        ensure(candidates.keys.isNotEmpty(), CoseFailure.KeyNotFound)
        val data = Structures.mac(
            context = Structures.MAC,
            protectedEncoding = message.protectedEncoding,
            externalAad = request.externalAad,
            payload = payload,
        )
        val keys = candidates.keys.map { bytes -> bytes.use { material -> SecretKey.of(material) } }
        val isValid = keys.any { key -> isValid(key = key, algorithm = algorithm, data = data, tag = message.tag) }
        keys.forEach { key -> key.destroy() }
        ensure(isValid, CoseFailure.InvalidTag)
        return payload
    }

    private suspend fun algorithmOf(
        protectedHeaders: CoseHeaders,
        unprotectedHeaders: CoseHeaders,
        request: Request,
    ): CoseAlgorithm {
        Layers.checkCritical(protectedHeaders = protectedHeaders, understood = understood)
        val algorithm = Layers.algorithmOf(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            allowed = request.algorithms,
            kind = CoseAlgorithmKind.Mac,
        )
        permissions.check(algorithm, AlgorithmUse.Verify)
        return algorithm
    }

    private suspend fun tag(key: SecretKey, algorithm: CoseAlgorithm, data: ByteString): ByteString {
        val mac = crypto.macs.mac(key = key, data = data, algorithm = algorithm.mac.sure())
        return mac.substring(startIndex = 0, endIndex = algorithm.tagBytes)
    }

    private suspend fun isValid(key: SecretKey, algorithm: CoseAlgorithm, data: ByteString, tag: ByteString): Boolean =
        ConstantTime.equals(first = tag(key = key, algorithm = algorithm, data = data), second = tag)
}
