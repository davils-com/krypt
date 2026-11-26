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

package com.davils.krypt.x509.internal

import com.davils.konnect.internetprotocol.address.IpAddress
import com.davils.konnect.internetprotocol.address.Ipv4Address
import com.davils.konnect.internetprotocol.address.Ipv6Address
import kotlinx.io.bytestring.ByteString

private const val IPV4: Int = 4
private const val IPV6: Int = 16

internal object IpAddresses {
    val SIZES: Set<Int> = setOf(IPV4, IPV4 * 2, IPV6, IPV6 * 2)

    fun parseOrNull(text: String): ByteString? {
        val address = IpAddress.parseOrNull(text) ?: return null
        return ByteString(address.toByteArray())
    }

    fun format(bytes: ByteString): String {
        val size = IPV6.takeIf { bytes.size >= IPV6 } ?: IPV4
        val address = formatAddress(bytes.substring(startIndex = 0, endIndex = size))
        val mask = bytes.substring(startIndex = size).takeIf { rest -> rest.size == size }
        val masked = mask?.let { found -> "$address/${formatAddress(found)}" }
        return masked ?: address
    }

    private fun formatAddress(bytes: ByteString): String {
        val raw = bytes.toByteArray()
        if (bytes.size == IPV4) return Ipv4Address.fromByteArray(raw).toString()
        return Ipv6Address.fromByteArray(raw).toString()
    }
}
