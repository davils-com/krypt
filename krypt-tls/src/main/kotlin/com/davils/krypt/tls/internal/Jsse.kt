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

import java.security.Provider
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSessionContext

internal object Jsse {
    private const val PROTOCOL: String = "TLS"

    fun context(provider: Provider?): SSLContext {
        if (provider == null) return SSLContext.getInstance(PROTOCOL)
        return SSLContext.getInstance(PROTOCOL, provider)
    }

    fun invalidate(context: SSLSessionContext) {
        val ids = context.ids.toList()
        ids.forEach { id -> context.getSession(id)?.invalidate() }
    }
}
