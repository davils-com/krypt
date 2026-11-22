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

import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseAlgorithmKind
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.CoseHeaders
import com.davils.krypt.cose.CoseSign
import com.davils.krypt.cose.CoseSign1
import com.davils.krypt.cose.CoseSignature
import com.davils.krypt.cose.CoseSigner
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.internal.CoseException.Companion.present
import com.davils.krypt.cose.internal.CoseException.Companion.refuse
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.signature.SignatureFormat
import kotlinx.io.bytestring.ByteString

internal class Signing(
    private val crypto: Crypto,
    private val permissions: Permissions,
    private val understood: List<CborItem>,
) {
    suspend fun sign1(
        payload: ByteString,
        signer: CoseSigner,
        externalAad: ByteString,
        isDetached: Boolean,
    ): CoseSign1 {
        val layer = layerOf(signer)
        val data = Structures.signature(
            context = Structures.SIGNATURE1,
            bodyProtected = layer.protectedEncoding,
            signerProtected = null,
            externalAad = externalAad,
            payload = payload,
        )
        return CoseSign1(
            protectedHeaders = layer.protectedHeaders,
            unprotectedHeaders = layer.unprotectedHeaders,
            payload = payload.takeUnless { isDetached },
            signature = sign(signer, data),
            protectedEncoding = layer.protectedEncoding,
        )
    }

    suspend fun sign(
        payload: ByteString,
        signers: List<CoseSigner>,
        body: Buckets,
        externalAad: ByteString,
        isDetached: Boolean,
    ): CoseSign {
        require(signers.isNotEmpty()) { "A COSE_Sign has at least one signer" }
        val signatures = signers.map { signer ->
            val layer = layerOf(signer)
            val data = Structures.signature(
                context = Structures.SIGNATURE,
                bodyProtected = body.protectedEncoding,
                signerProtected = layer.protectedEncoding,
                externalAad = externalAad,
                payload = payload,
            )
            CoseSignature(
                protectedHeaders = layer.protectedHeaders,
                unprotectedHeaders = layer.unprotectedHeaders,
                signature = sign(signer, data),
                protectedEncoding = layer.protectedEncoding,
            )
        }
        return CoseSign(
            protectedHeaders = body.protectedHeaders,
            unprotectedHeaders = body.unprotectedHeaders,
            payload = payload.takeUnless { isDetached },
            signatures = signatures,
            protectedEncoding = body.protectedEncoding,
        )
    }

    suspend fun verify(message: CoseSign1, request: Request): ByteString {
        val payload = Payloads.of(attached = message.payload, detached = request.detached)
        val data = Structures.signature(
            context = Structures.SIGNATURE1,
            bodyProtected = message.protectedEncoding,
            signerProtected = null,
            externalAad = request.externalAad,
            payload = payload,
        )
        verifyLayer(
            protectedHeaders = message.protectedHeaders,
            unprotectedHeaders = message.unprotectedHeaders,
            request = request,
            data = data,
            signature = message.signature,
        )
        return payload
    }

    suspend fun verify(message: CoseSign, request: Request): CoseSignature {
        val payload = Payloads.of(attached = message.payload, detached = request.detached)
        Layers.checkCritical(protectedHeaders = message.protectedHeaders, understood = understood)
        val failures = mutableListOf<CoseFailure>()
        val verified = message.signatures.firstOrNull { signature ->
            val data = Structures.signature(
                context = Structures.SIGNATURE,
                bodyProtected = message.protectedEncoding,
                signerProtected = signature.protectedEncoding,
                externalAad = request.externalAad,
                payload = payload,
            )
            val failure = CoseException.failureOf {
                verifyLayer(
                    protectedHeaders = signature.protectedHeaders,
                    unprotectedHeaders = signature.unprotectedHeaders,
                    request = request,
                    data = data,
                    signature = signature.signature,
                )
            }
            failure?.let { found -> failures += found }
            failure == null
        }
        return verified ?: refuse(failures.maxBy { failure -> PROGRESS.indexOf(failure) })
    }

    private suspend fun verifyLayer(
        protectedHeaders: CoseHeaders,
        unprotectedHeaders: CoseHeaders,
        request: Request,
        data: ByteString,
        signature: ByteString,
    ) {
        Layers.checkCritical(protectedHeaders = protectedHeaders, understood = understood)
        val algorithm = Layers.algorithmOf(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = unprotectedHeaders,
            allowed = request.algorithms,
            kind = CoseAlgorithmKind.Signature,
        )
        permissions.check(algorithm, AlgorithmUse.Verify)
        val keyId = Layers.keyIdOf(protectedHeaders = protectedHeaders, unprotectedHeaders = unprotectedHeaders)
        val candidates = request.keys.filter { key ->
            KeyFit.canVerify(key, algorithm) && KeyFit.isKeyIdFit(key, keyId)
        }
        ensure(candidates.isNotEmpty(), CoseFailure.KeyNotFound)
        val isValid = candidates.any { key ->
            isValid(key = key, algorithm = algorithm, data = data, signature = signature)
        }
        ensure(isValid, CoseFailure.InvalidSignature)
    }

    private suspend fun isValid(
        key: CoseKey,
        algorithm: CoseAlgorithm,
        data: ByteString,
        signature: ByteString,
    ): Boolean {
        val publicKey = present(key.publicKey, CoseFailure.KeyNotFound)
        val signatureAlgorithm = Permissions.signatureOf(algorithm, key.curve)
        val isPermitted = permissions.isPermitted(signatureAlgorithm, AlgorithmUse.Verify) &&
            permissions.isKeyPermitted(publicKey, AlgorithmUse.Verify)
        val fieldBytes = key.curve?.curve?.fieldBytes
        val isSized = fieldBytes == null || signature.size == 2 * fieldBytes
        val isFit = isPermitted && isSized
        if (!isFit) return false
        val verification = crypto.signatures.verify(
            key = publicKey,
            data = data,
            signature = signature,
            algorithm = signatureAlgorithm,
            format = SignatureFormat.Raw,
        )
        return verification.isValid
    }

    private suspend fun sign(signer: CoseSigner, data: ByteString): ByteString = crypto.signatures.sign(
        key = signer.key.privateKey.sure(),
        data = data,
        algorithm = Permissions.signatureOf(signer.algorithm, signer.key.curve),
        format = SignatureFormat.Raw,
    )

    private fun layerOf(signer: CoseSigner): Buckets {
        val protectedHeaders = Layers.withAlgorithm(
            protectedHeaders = signer.protectedHeaders,
            unprotectedHeaders = signer.unprotectedHeaders,
            algorithm = signer.algorithm,
        )
        val unprotectedHeaders = Layers.withKeyId(
            protectedHeaders = protectedHeaders,
            unprotectedHeaders = signer.unprotectedHeaders,
            keyId = signer.key.keyId,
        )
        Layers.requireDistinct(protectedHeaders = protectedHeaders, unprotectedHeaders = unprotectedHeaders)
        return Buckets(
            protectedHeaders = protectedHeaders,
            protectedEncoding = Layers.encodingOf(protectedHeaders),
            unprotectedHeaders = unprotectedHeaders,
        )
    }

    private companion object {
        val PROGRESS: List<CoseFailure> = listOf(
            CoseFailure.Malformed,
            CoseFailure.UnknownCritical,
            CoseFailure.AlgorithmNotPermitted,
            CoseFailure.KeyNotFound,
            CoseFailure.InvalidSignature,
        )
    }
}
