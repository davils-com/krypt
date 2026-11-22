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

package com.davils.krypt.tls.internal

import com.davils.krypt.x509.name.GeneralName

internal object HostNames {
    private const val MAXIMUM_NAME: Int = 253
    private const val MAXIMUM_LABEL: Int = 63

    fun isDnsName(host: String): Boolean {
        val name = host.lowercase().removeSuffix(".")
        val isSized = name.length in 1..MAXIMUM_NAME
        return isSized && name.split('.').all { label -> isLabel(label) } && !isIpAddress(name)
    }

    fun isHost(host: String): Boolean = isDnsName(host) || isIpAddress(host)

    private fun isIpAddress(host: String): Boolean =
        GeneralName.IpAddress.parseOrNull(host.removePrefix("[").removeSuffix("]")) != null

    private fun isLabel(label: String): Boolean {
        val isSized = label.length in 1..MAXIMUM_LABEL
        val isLdh = label.all { char -> char in 'a'..'z' || char in '0'..'9' || char == '-' }
        return isSized && isLdh && !label.startsWith('-') && !label.endsWith('-')
    }
}
