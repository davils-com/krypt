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

package com.davils.krypt.stream.internal

import com.davils.krypt.core.ConstantTime
import com.davils.krypt.core.SecretBytes
import com.davils.krypt.core.policy.AlgorithmUse
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.stream.Credential
import com.davils.krypt.stream.StreamFailure
import com.davils.krypt.stream.StreamLimits
import com.davils.krypt.stream.internal.StreamRefusal.Companion.refuse
import kotlinx.io.bytestring.ByteString

internal class Unlocking(private val crypto: Crypto, private val limits: StreamLimits) {
    suspend fun unlock(header: Header, credentials: List<Credential>, associatedData: ByteString): Unlocked {
        val aead = header.suite.aead
        StreamRefusal.ensure(crypto.environment.policy.permits(aead, AlgorithmUse.Verify), StreamFailure.Refused)
        StreamRefusal.ensure(crypto.capabilities.supports(aead), StreamFailure.Unsupported)
        val context = KeySchedule.context(crypto = crypto, core = header.core, associatedData = associatedData)
        val wrapContext = Octets.concat(KeySchedule.RECIPIENT_LABEL, header.core)
        val dataKey = dataKeyOf(header = header, credentials = credentials, context = wrapContext)
            ?: refuse(StreamFailure.NotARecipient)
        val schedule = KeySchedule.derive(
            crypto = crypto,
            dataKey = dataKey,
            salt = header.salt,
            context = context,
            suite = header.suite,
        )
        val isCommitted = ConstantTime.equals(first = schedule.commitment, second = header.commitment)
        val mac = crypto.macs.verify(key = schedule.macKey, data = header.authenticated, tag = header.mac)
        val isAuthentic = isCommitted && mac.isValid
        if (!isAuthentic) {
            schedule.destroy()
            dataKey.destroy()
        }
        StreamRefusal.ensure(isAuthentic, StreamFailure.DecryptionFailed)
        val cipher = SegmentCipher(
            crypto = crypto,
            suite = header.suite,
            key = schedule.payload,
            prefix = header.noncePrefix,
        )
        return Unlocked(header = header, dataKey = dataKey, schedule = schedule, cipher = cipher)
    }

    private suspend fun dataKeyOf(header: Header, credentials: List<Credential>, context: ByteString): SecretBytes? {
        val wrapping = Wrapping(crypto, limits)
        for (credential in credentials) {
            for (entry in header.recipients) {
                val key = wrapping.unwrap(credential = credential, entry = entry, context = context)
                val fitting = key?.takeIf { found -> found.size == KeySchedule.DATA_KEY_BYTES }
                if (fitting != null) return fitting
                key?.destroy()
            }
        }
        return null
    }
}
