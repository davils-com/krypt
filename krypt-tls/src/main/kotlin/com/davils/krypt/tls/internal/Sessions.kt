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

import java.net.Socket
import javax.net.ssl.ExtendedSSLSession
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket

internal object Sessions {
    fun of(socket: Socket?): SSLSession? = (socket as? SSLSocket)?.handshakeSession

    fun of(engine: SSLEngine?): SSLSession? = engine?.handshakeSession

    fun requestedHost(session: SSLSession?): String? {
        val names = (session as? ExtendedSSLSession)?.requestedServerNames.orEmpty()
        return names.filterIsInstance<SNIHostName>().firstOrNull()?.asciiName
    }

    fun staples(session: SSLSession?): List<ByteArray> = (session as? ExtendedSSLSession)?.statusResponses.orEmpty()
}
