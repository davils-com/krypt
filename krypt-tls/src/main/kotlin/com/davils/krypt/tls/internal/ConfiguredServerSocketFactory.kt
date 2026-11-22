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
import java.net.ServerSocket
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLServerSocketFactory

internal class ConfiguredServerSocketFactory(
    private val delegate: SSLServerSocketFactory,
    private val parameters: () -> SSLParameters,
) : SSLServerSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = parameters().cipherSuites

    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    override fun createServerSocket(): ServerSocket = configured(delegate.createServerSocket())

    override fun createServerSocket(port: Int): ServerSocket = configured(delegate.createServerSocket(port))

    override fun createServerSocket(port: Int, backlog: Int): ServerSocket =
        configured(delegate.createServerSocket(port, backlog))

    override fun createServerSocket(port: Int, backlog: Int, address: InetAddress?): ServerSocket =
        configured(delegate.createServerSocket(port, backlog, address))

    private fun configured(socket: ServerSocket): ServerSocket {
        val secured = socket as SSLServerSocket
        secured.sslParameters = parameters()
        return secured
    }
}
