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

import com.davils.kore.core.outcome.getOrNull
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.cose.CoseAlgorithm
import com.davils.krypt.cose.CoseFailure
import com.davils.krypt.cose.cbor.CborArray
import com.davils.krypt.cose.cbor.CborItem
import com.davils.krypt.cose.cbor.CborMap
import com.davils.krypt.cose.internal.CoseException.Companion.ensure
import com.davils.krypt.cose.internal.CoseException.Companion.present
import com.davils.krypt.cose.internal.CoseException.Companion.refuse
import com.davils.krypt.cose.key.CoseCurve
import com.davils.krypt.cose.key.CoseKey
import com.davils.krypt.cose.key.CoseKeyOperation
import com.davils.krypt.cose.key.CoseKeyType
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.primitive.key.PrivateKey
import com.davils.krypt.primitive.key.PublicKey
import com.davils.krypt.primitive.key.SecretKey
import kotlinx.io.bytestring.ByteString

internal class KeyCodec(private val crypto: Crypto) {
    suspend fun decode(map: CborMap): CoseKey {
        val typeId = present(map[LABEL_TYPE], CoseFailure.Malformed)
        val type = CoseKeyType.entries.firstOrNull { candidate -> typeId.longOrNull() == candidate.id }
        val algorithmItem = map[LABEL_ALGORITHM]
        val algorithm = algorithmItem?.let { item -> present(item.longOrNull(), CoseFailure.UnsupportedKey) }
        val known = algorithm?.let { id -> present(CoseAlgorithm.of(id), CoseFailure.UnsupportedKey) }
        val parts = KeyParts(
            type = present(type, CoseFailure.UnsupportedKey),
            keyId = optionalBytes(map, LABEL_KEY_ID),
            algorithm = known,
            operations = operationsOf(map),
            baseIv = optionalBytes(map, LABEL_BASE_IV),
        )
        return when (parts.type) {
            CoseKeyType.Okp -> okp(map, parts)
            CoseKeyType.Ec2 -> ec2(map, parts)
            CoseKeyType.Rsa -> rsa(map, parts)
            CoseKeyType.Symmetric -> symmetric(map, parts)
        }
    }

    fun encode(key: CoseKey, isPrivateIncluded: Boolean): CborMap {
        val common = listOf(
            LABEL_TYPE to labelOf(key.type.id),
            LABEL_KEY_ID to key.keyId?.let { bytes -> bytesOf(bytes) },
            LABEL_ALGORITHM to key.algorithm?.let { algorithm -> labelOf(algorithm.id) },
            LABEL_OPERATIONS to operationsItem(key.operations),
            LABEL_BASE_IV to key.baseIv?.let { bytes -> bytesOf(bytes) },
        )
        return mapOf(common + material(key = key, isPrivateIncluded = isPrivateIncluded))
    }

    fun required(key: CoseKey): CborMap {
        val material = material(key = key, isPrivateIncluded = key.type == CoseKeyType.Symmetric)
        val kept = material.filter { (label, _) -> label in REQUIRED_LABELS }
        return mapOf(listOf(LABEL_TYPE to labelOf(key.type.id)) + kept)
    }

    private fun material(key: CoseKey, isPrivateIncluded: Boolean): List<Pair<Long, CborItem?>> = when (key.type) {
        CoseKeyType.Okp -> okpMaterial(key, isPrivateIncluded)
        CoseKeyType.Ec2 -> ec2Material(key, isPrivateIncluded)
        CoseKeyType.Rsa -> rsaMaterial(key, isPrivateIncluded)
        CoseKeyType.Symmetric -> symmetricMaterial(key)
    }

    private suspend fun okp(map: CborMap, parts: KeyParts): CoseKey {
        val curve = curveOf(map, CoseKeyType.Okp)
        val x = sizedBytes(map, LABEL_X, curve.size)
        val d = sizedBytes(map, LABEL_OKP_D, curve.size)
        ensure(x != null || d != null, CoseFailure.Malformed)
        val publicKey = x?.let { bytes -> publicOf(KeyMaterial.okpSpki(curve = curve, x = bytes)) }
        val privateKey = d?.let { bytes -> privateOf(KeyMaterial.okpPkcs8(curve = curve, d = bytes, x = x)) }
        return parts.assemble(curve = curve, publicKey = publicKey, privateKey = privateKey, secretKey = null)
    }

    private suspend fun ec2(map: CborMap, parts: KeyParts): CoseKey {
        val curve = curveOf(map, CoseKeyType.Ec2)
        ensure(map[LABEL_Y]?.simpleOrNull() == null, CoseFailure.UnsupportedKey)
        val coordinates = listOfNotNull(sizedBytes(map, LABEL_X, curve.size), sizedBytes(map, LABEL_Y, curve.size))
        val d = sizedBytes(map, LABEL_EC_D, curve.size)
        ensure(coordinates.size != 1 && (coordinates.isNotEmpty() || d != null), CoseFailure.Malformed)
        val point = coordinates.takeIf { found -> found.isNotEmpty() }?.let { found -> KeyMaterial.point(found) }
        val publicKey = point?.let { found -> publicOf(KeyMaterial.ecSpki(curve = curve, point = found)) }
        val privateKey = d?.let { bytes -> privateOf(KeyMaterial.ecPkcs8(curve = curve, d = bytes, point = point)) }
        return parts.assemble(curve = curve, publicKey = publicKey, privateKey = privateKey, secretKey = null)
    }

    private suspend fun rsa(map: CborMap, parts: KeyParts): CoseKey {
        ensure(map[LABEL_RSA_OTHER] == null, CoseFailure.UnsupportedKey)
        val modulus = present(sizedBytes(map, LABEL_RSA_N, null), CoseFailure.Malformed)
        val exponent = present(sizedBytes(map, LABEL_RSA_E, null), CoseFailure.Malformed)
        val secrets = RSA_PRIVATE_LABELS.map { label -> sizedBytes(map, label, null) }
        val isComplete = secrets.all { secret -> secret != null }
        ensure(isComplete || secrets.all { secret -> secret == null }, CoseFailure.Malformed)
        val publicKey = publicOf(KeyMaterial.rsaSpki(modulus = modulus, exponent = exponent))
        val privateParts = listOf(modulus, exponent) + secrets.filterNotNull()
        val privateKey = privateParts.takeIf { isComplete }?.let { values -> privateOf(KeyMaterial.rsaPkcs8(values)) }
        return parts.assemble(curve = null, publicKey = publicKey, privateKey = privateKey, secretKey = null)
    }

    private fun symmetric(map: CborMap, parts: KeyParts): CoseKey {
        val bytes = present(sizedBytes(map, LABEL_K, null), CoseFailure.Malformed)
        ensure(bytes.size >= SecretKey.MINIMUM_BYTES, CoseFailure.UnsupportedKey)
        val secret = SecretBytes.copyOf(bytes).use { material -> SecretKey.of(material) }
        return parts.assemble(curve = null, publicKey = null, privateKey = null, secretKey = secret)
    }

    private fun okpMaterial(key: CoseKey, isPrivateIncluded: Boolean): List<Pair<Long, CborItem?>> {
        val curve = key.curve.sure()
        val x = publicOf(key)?.let { spki -> KeyMaterial.publicBits(spki) }
        val d = privateInner(key, isPrivateIncluded)?.let { inner -> KeyMaterial.okpPrivate(inner) }
        return listOf(
            LABEL_CURVE to labelOf(curve.id),
            LABEL_X to x?.let { bytes -> bytesOf(bytes) },
            LABEL_OKP_D to d?.let { bytes -> bytesOf(bytes) },
        )
    }

    private fun ec2Material(key: CoseKey, isPrivateIncluded: Boolean): List<Pair<Long, CborItem?>> {
        val curve = key.curve.sure()
        val point = publicOf(key)?.let { spki -> KeyMaterial.ecCoordinates(spki, curve.size) }
        val d = privateInner(key, isPrivateIncluded)?.let { inner -> KeyMaterial.ecPrivate(inner) }
        val padded = d?.let { bytes -> Bytes.leftPadded(bytes, curve.size) }
        return listOf(
            LABEL_CURVE to labelOf(curve.id),
            LABEL_X to point?.let { found -> bytesOf(found.first) },
            LABEL_Y to point?.let { found -> bytesOf(found.second) },
            LABEL_EC_D to padded?.let { bytes -> bytesOf(bytes) },
        )
    }

    private fun rsaMaterial(key: CoseKey, isPrivateIncluded: Boolean): List<Pair<Long, CborItem?>> {
        val public = KeyMaterial.rsaPublic(publicOf(key).sure())
        val privateParts = privateInner(key, isPrivateIncluded)?.let { inner -> KeyMaterial.rsaPrivate(inner) }
        val private = privateParts.orEmpty()
        val publicEntries = listOf(LABEL_RSA_N, LABEL_RSA_E).zip(public)
        val privateEntries = RSA_PRIVATE_LABELS.zip(private.drop(RSA_PUBLIC_PARTS))
        return (publicEntries + privateEntries).map { (label, bytes) -> label to bytesOf(bytes) }
    }

    private fun symmetricMaterial(key: CoseKey): List<Pair<Long, CborItem?>> {
        val exported = key.secretKey.sure().export()
        val bytes = exported.use { material -> material.reveal { raw -> ByteString(raw) } }
        return listOf(LABEL_K to bytesOf(bytes))
    }

    private fun publicOf(key: CoseKey): ByteString? = (key.publicKey ?: key.privateKey.sure().publicKey)?.encoded

    private fun privateInner(key: CoseKey, isPrivateIncluded: Boolean): ByteString? {
        val privateKey = key.privateKey?.takeIf { isPrivateIncluded } ?: return null
        return crypto.keys.encodePrivate(privateKey).use { encoding ->
            encoding.reveal { bytes -> KeyMaterial.privateValue(ByteString(bytes)) }
        }
    }

    private fun publicOf(spki: ByteString): PublicKey =
        present(crypto.keys.decodePublic(spki).getOrNull(), CoseFailure.UnsupportedKey)

    private suspend fun privateOf(pkcs8: SecretBytes): PrivateKey = pkcs8.use { encoding ->
        present(crypto.keys.decodePrivate(encoding).getOrNull(), CoseFailure.UnsupportedKey)
    }

    private fun curveOf(map: CborMap, type: CoseKeyType): CoseCurve {
        val item = present(map[LABEL_CURVE], CoseFailure.Malformed)
        val curve = CoseCurve.entries.firstOrNull { candidate ->
            candidate.keyType == type && item.longOrNull() == candidate.id
        }
        return present(curve, CoseFailure.UnsupportedKey)
    }

    private fun sizedBytes(map: CborMap, label: Long, size: Int?): ByteString? {
        val item = map[label] ?: return null
        val bytes = present(item.bytesOrNull(), CoseFailure.Malformed)
        ensure(size == null || bytes.size == size, CoseFailure.Malformed)
        return bytes
    }

    private fun optionalBytes(map: CborMap, label: Long): ByteString? = sizedBytes(map, label, null)

    private fun operationsOf(map: CborMap): Set<CoseKeyOperation> {
        val item = map[LABEL_OPERATIONS] ?: return emptySet()
        val values = present(item.itemsOrNull(), CoseFailure.Malformed)
        val operations = values.map { value ->
            val id = value.longOrNull()
            val operation = CoseKeyOperation.entries.firstOrNull { candidate -> id == candidate.id }
            present(operation, CoseFailure.UnsupportedKey)
        }
        return operations.toSet()
    }

    private fun operationsItem(operations: Set<CoseKeyOperation>): CborItem? {
        val sorted = operations.sortedBy { operation -> operation.id }
        return CborArray(sorted.map { operation -> labelOf(operation.id) }).takeIf { sorted.isNotEmpty() }
    }

    private fun mapOf(entries: List<Pair<Long, CborItem?>>): CborMap =
        CborMap(entries.mapNotNull { (label, value) -> value?.let { found -> labelOf(label) to found } })

    private class KeyParts(
        val type: CoseKeyType,
        val keyId: ByteString?,
        val algorithm: CoseAlgorithm?,
        val operations: Set<CoseKeyOperation>,
        val baseIv: ByteString?,
    ) {
        fun assemble(
            curve: CoseCurve?,
            publicKey: PublicKey?,
            privateKey: PrivateKey?,
            secretKey: SecretKey?,
        ): CoseKey {
            val isFit = algorithm == null || KeyFit.isTypeFit(type = type, curve = curve, algorithm = algorithm)
            if (!isFit) refuse(CoseFailure.UnsupportedKey)
            val isIvFit = baseIv == null || type == CoseKeyType.Symmetric
            ensure(isIvFit, CoseFailure.Malformed)
            return CoseKey(
                type = type,
                curve = curve,
                keyId = keyId,
                algorithm = algorithm,
                operations = operations,
                baseIv = baseIv,
                publicKey = publicKey,
                privateKey = privateKey,
                secretKey = secretKey,
            )
        }
    }

    private companion object {
        const val LABEL_TYPE: Long = 1
        const val LABEL_KEY_ID: Long = 2
        const val LABEL_ALGORITHM: Long = 3
        const val LABEL_OPERATIONS: Long = 4
        const val LABEL_BASE_IV: Long = 5
        const val LABEL_CURVE: Long = -1
        const val LABEL_K: Long = -1
        const val LABEL_X: Long = -2
        const val LABEL_Y: Long = -3
        const val LABEL_EC_D: Long = -4
        const val LABEL_OKP_D: Long = -4
        const val LABEL_RSA_N: Long = -1
        const val LABEL_RSA_E: Long = -2
        const val LABEL_RSA_OTHER: Long = -9
        const val RSA_PUBLIC_PARTS: Int = 2
        val RSA_PRIVATE_LABELS: List<Long> = listOf(-3L, -4L, -5L, -6L, -7L, -8L)
        val REQUIRED_LABELS: Set<Long> = setOf(LABEL_CURVE, LABEL_X, LABEL_Y)
    }
}
