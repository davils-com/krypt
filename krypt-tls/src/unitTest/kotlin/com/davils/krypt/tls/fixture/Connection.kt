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

import java.nio.ByteBuffer
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLEngineResult
import javax.net.ssl.SSLException

private const val BUFFER_BYTES: Int = 1 shl 17
private const val ROUNDS: Int = 24

internal class Connection(val client: SSLEngine, val server: SSLEngine) {
    private val toServer: ByteBuffer = ByteBuffer.allocate(BUFFER_BYTES)

    private val toClient: ByteBuffer = ByteBuffer.allocate(BUFFER_BYTES)

    private val clientData: ByteBuffer = ByteBuffer.allocate(BUFFER_BYTES)

    private val serverData: ByteBuffer = ByteBuffer.allocate(BUFFER_BYTES)

    val failures: MutableList<Throwable> = mutableListOf()

    val isEstablished: Boolean
        get() = failures.isEmpty() && isSettled(client) && isSettled(server)

    fun handshake(): Connection {
        client.beginHandshake()
        server.beginHandshake()
        pump()
        return this
    }

    fun send(text: String): String {
        val source = ByteBuffer.wrap(text.encodeToByteArray())
        attempt(client) { client.wrap(source, toServer) }
        pump()
        serverData.flip()
        val bytes = ByteArray(serverData.remaining())
        serverData.get(bytes)
        serverData.clear()
        return bytes.decodeToString()
    }

    private fun pump() {
        repeat(ROUNDS) {
            step(engine = client, outgoing = toServer, incoming = toClient, data = clientData)
            step(engine = server, outgoing = toClient, incoming = toServer, data = serverData)
        }
    }

    private fun step(engine: SSLEngine, outgoing: ByteBuffer, incoming: ByteBuffer, data: ByteBuffer) {
        attempt(engine) { engine.wrap(ByteBuffer.allocate(0), outgoing) }
        incoming.flip()
        attempt(engine) { engine.unwrap(incoming, data) }
        incoming.compact()
    }

    private fun attempt(engine: SSLEngine, block: () -> SSLEngineResult) {
        try {
            block()
            generateSequence { engine.delegatedTask }.forEach { task -> task.run() }
        } catch (failure: SSLException) {
            failures += failure
        }
    }

    private fun isSettled(engine: SSLEngine): Boolean =
        engine.handshakeStatus == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING && engine.session.isValid
}
