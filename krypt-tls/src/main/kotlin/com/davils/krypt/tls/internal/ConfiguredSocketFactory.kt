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

import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

internal class ConfiguredSocketFactory(
    private val delegate: SSLSocketFactory,
    private val suites: List<String>,
    private val configure: (SSLSocket, String?) -> SSLSocket,
) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = suites.toTypedArray()

    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    override fun createSocket(): Socket = configure(delegate.createSocket() as SSLSocket, null)

    override fun createSocket(socket: Socket?, host: String?, port: Int, autoClose: Boolean): Socket =
        configure(delegate.createSocket(socket, host, port, autoClose) as SSLSocket, host)

    override fun createSocket(host: String?, port: Int): Socket =
        configure(delegate.createSocket(host, port) as SSLSocket, host)

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        configure(delegate.createSocket(host, port, localHost, localPort) as SSLSocket, host)

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        configure(delegate.createSocket(host, port) as SSLSocket, null)

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        configure(delegate.createSocket(address, port, localAddress, localPort) as SSLSocket, null)
}
