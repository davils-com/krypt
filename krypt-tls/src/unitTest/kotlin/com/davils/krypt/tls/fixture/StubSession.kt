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

package com.davils.krypt.tls.fixture

import java.security.Principal
import java.security.cert.Certificate
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLSessionContext

internal class StubSession(
    private val staples: List<ByteArray>,
    private val serverName: String? = null,
    private val host: String? = null,
) : ExtendedSSLSession() {
    private val values: MutableMap<String, Any> = mutableMapOf()

    override fun getStatusResponses(): List<ByteArray> = staples

    override fun getRequestedServerNames(): List<SNIServerName> = listOfNotNull(serverName?.let { SNIHostName(it) })

    override fun getLocalSupportedSignatureAlgorithms(): Array<String> = emptyArray()

    override fun getPeerSupportedSignatureAlgorithms(): Array<String> = emptyArray()

    override fun getId(): ByteArray = ByteArray(0)

    override fun getSessionContext(): SSLSessionContext? = null

    override fun getCreationTime(): Long = 0L

    override fun getLastAccessedTime(): Long = 0L

    override fun invalidate() = Unit

    override fun isValid(): Boolean = true

    override fun putValue(name: String, value: Any) {
        values[name] = value
    }

    override fun getValue(name: String): Any? = values[name]

    override fun removeValue(name: String) {
        values.remove(name)
    }

    override fun getValueNames(): Array<String> = values.keys.toTypedArray()

    override fun getPeerCertificates(): Array<Certificate> = emptyArray()

    override fun getLocalCertificates(): Array<Certificate> = emptyArray()

    override fun getPeerPrincipal(): Principal? = null

    override fun getLocalPrincipal(): Principal? = null

    override fun getCipherSuite(): String = ""

    override fun getProtocol(): String = ""

    override fun getPeerHost(): String? = host

    override fun getPeerPort(): Int = -1

    override fun getPacketBufferSize(): Int = 0

    override fun getApplicationBufferSize(): Int = 0
}
