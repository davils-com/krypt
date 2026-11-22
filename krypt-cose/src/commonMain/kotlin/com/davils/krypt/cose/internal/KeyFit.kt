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

import com.davils.krypt.core.algorithm.KeyFamily
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseAlgorithmKind
import com.davils.krypt.cose.key.CoseCurve
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeyOperation
import com.davils.krypt.cose.key.CoseKeyType
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

internal object KeyFit {
    private val AGREEMENT_CURVES: Set<CoseCurve> =
        setOf(CoseCurve.P256, CoseCurve.P384, CoseCurve.P521, CoseCurve.X25519, CoseCurve.X448)
    private val EDWARDS_CURVES: Set<CoseCurve> = setOf(CoseCurve.Ed25519, CoseCurve.Ed448)
    private val DERIVATIONS: Set<CoseKeyOperation> = setOf(CoseKeyOperation.DeriveKey, CoseKeyOperation.DeriveBits)

    fun isTypeFit(key: CoseKey, algorithm: CoseAlgorithm): Boolean =
        isTypeFit(type = key.type, curve = key.curve, algorithm = algorithm)

    fun isTypeFit(type: CoseKeyType, curve: CoseCurve?, algorithm: CoseAlgorithm): Boolean = when (algorithm.kind) {
        CoseAlgorithmKind.Signature -> isSignatureFit(type, curve, algorithm)
        CoseAlgorithmKind.Mac -> type == CoseKeyType.Symmetric
        CoseAlgorithmKind.ContentEncryption -> type == CoseKeyType.Symmetric
        CoseAlgorithmKind.KeyDistribution -> isDistributionFit(type, curve, algorithm)
    }

    fun canSign(key: CoseKey, algorithm: CoseAlgorithm): Boolean =
        fits(key, algorithm, setOf(CoseKeyOperation.Sign)) && key.privateKey != null

    fun canVerify(key: CoseKey, algorithm: CoseAlgorithm): Boolean =
        fits(key, algorithm, setOf(CoseKeyOperation.Verify)) && key.publicKey != null

    fun canAgree(key: CoseKey, algorithm: CoseAlgorithm): Boolean =
        isTypeFit(key, algorithm) && isAlgorithmFit(key, algorithm) && key.publicKey != null

    fun canDerive(key: CoseKey, algorithm: CoseAlgorithm): Boolean =
        fits(key, algorithm, DERIVATIONS) && key.privateKey != null

    fun secretOf(key: CoseKey, algorithm: CoseAlgorithm, operation: CoseKeyOperation, bytes: Int?): SecretKey? {
        val secret = key.secretKey?.takeIf { fits(key, algorithm, setOf(operation)) }
        val isSized = bytes == null || secret?.bits == bytes * Byte.SIZE_BITS
        return secret?.takeIf { found -> isSized && !found.isDestroyed }
    }

    fun macKeyOf(key: CoseKey, algorithm: CoseAlgorithm, operation: CoseKeyOperation): SecretKey? {
        val secret = secretOf(key = key, algorithm = algorithm, operation = operation, bytes = null)
        val digest = algorithm.mac.sure().digest
        val minimumBits = digest.outputBytes * Byte.SIZE_BITS
        return secret?.takeIf { found -> found.bits >= minimumBits }
    }

    fun isKeyIdFit(key: CoseKey, keyId: ByteString?): Boolean = keyId == null || key.keyId == null || key.keyId == keyId

    private fun fits(key: CoseKey, algorithm: CoseAlgorithm, operations: Set<CoseKeyOperation>): Boolean {
        val isOperationFit = key.operations.isEmpty() || key.operations.any { operation -> operation in operations }
        return isTypeFit(key, algorithm) && isAlgorithmFit(key, algorithm) && isOperationFit
    }

    private fun isAlgorithmFit(key: CoseKey, algorithm: CoseAlgorithm): Boolean =
        key.algorithm == null || key.algorithm == algorithm

    private fun isSignatureFit(type: CoseKeyType, curve: CoseCurve?, algorithm: CoseAlgorithm): Boolean {
        val isCurveFit = algorithm.curve != null && curve == algorithm.curve
        val isEdDsa = algorithm == CoseAlgorithm.EdDsa && curve in EDWARDS_CURVES
        val isRsa = algorithm.signature?.family == KeyFamily.Rsa && type == CoseKeyType.Rsa
        return isCurveFit || isEdDsa || isRsa
    }

    private fun isDistributionFit(type: CoseKeyType, curve: CoseCurve?, algorithm: CoseAlgorithm): Boolean {
        val isAgreement = algorithm.kdf != null
        val isAgreementKey = curve in AGREEMENT_CURVES
        return listOf(type == CoseKeyType.Symmetric, isAgreementKey)[isAgreement.compareTo(false)]
    }
}
