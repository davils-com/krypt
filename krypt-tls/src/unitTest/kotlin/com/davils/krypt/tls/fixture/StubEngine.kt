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
import javax.net.ssl.SSLSession

internal class StubEngine(private val session: SSLSession) : SSLEngine() {
    override fun getHandshakeSession(): SSLSession = session

    override fun wrap(
        sources: Array<out ByteBuffer>?,
        offset: Int,
        length: Int,
        target: ByteBuffer?,
    ): SSLEngineResult = throw UnsupportedOperationException(UNSUPPORTED)

    override fun unwrap(
        source: ByteBuffer?,
        targets: Array<out ByteBuffer>?,
        offset: Int,
        length: Int,
    ): SSLEngineResult = throw UnsupportedOperationException(UNSUPPORTED)

    override fun getDelegatedTask(): Runnable? = null

    override fun closeInbound() = Unit

    override fun isInboundDone(): Boolean = true

    override fun closeOutbound() = Unit

    override fun isOutboundDone(): Boolean = true

    override fun getSupportedCipherSuites(): Array<String> = emptyArray()

    override fun getEnabledCipherSuites(): Array<String> = emptyArray()

    override fun setEnabledCipherSuites(suites: Array<out String>?) = Unit

    override fun getSupportedProtocols(): Array<String> = emptyArray()

    override fun getEnabledProtocols(): Array<String> = emptyArray()

    override fun setEnabledProtocols(protocols: Array<out String>?) = Unit

    override fun getSession(): SSLSession = session

    override fun beginHandshake() = Unit

    override fun getHandshakeStatus(): SSLEngineResult.HandshakeStatus = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING

    override fun setUseClientMode(mode: Boolean) = Unit

    override fun getUseClientMode(): Boolean = true

    override fun setNeedClientAuth(need: Boolean) = Unit

    override fun getNeedClientAuth(): Boolean = false

    override fun setWantClientAuth(want: Boolean) = Unit

    override fun getWantClientAuth(): Boolean = false

    override fun setEnableSessionCreation(flag: Boolean) = Unit

    override fun getEnableSessionCreation(): Boolean = true

    private companion object {
        const val UNSUPPORTED: String = "A stub engine moves no data"
    }
}
