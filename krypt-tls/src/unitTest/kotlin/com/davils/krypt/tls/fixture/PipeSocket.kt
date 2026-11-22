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

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.nio.channels.Channels
import java.nio.channels.Pipe

internal class PipeSocket private constructor(private val input: InputStream, private val output: OutputStream) :
    Socket() {
    override fun isConnected(): Boolean = true

    override fun getInputStream(): InputStream = input

    override fun getOutputStream(): OutputStream = output

    override fun getPort(): Int = PORT

    override fun getInetAddress(): InetAddress = InetAddress.getLoopbackAddress()

    override fun close() {
        input.close()
        output.close()
    }

    companion object {
        fun <T> connected(block: (PipeSocket, PipeSocket) -> T): T {
            val toServer = Pipe.open()
            val toClient = Pipe.open()
            return PipeSocket(input = inputOf(toClient), output = outputOf(toServer)).use { client ->
                PipeSocket(input = inputOf(toServer), output = outputOf(toClient)).use { server ->
                    block(client, server)
                }
            }
        }

        private fun inputOf(pipe: Pipe): InputStream = Channels.newInputStream(pipe.source())

        private fun outputOf(pipe: Pipe): OutputStream = Channels.newOutputStream(pipe.sink())
    }
}
