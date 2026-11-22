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

package com.davils.krypt.acme

/**
 * How the ACME client reaches the server: krypt opens no socket, so the application sends each request over its own
 * HTTP client.
 *
 * The transport sends the method, the URL, the header fields and the body of the request as they are, adds the
 * `User-Agent` field RFC 8555 requires, follows no redirect, and hands back the status, every header field and the
 * body. It may refuse a body larger than the [AcmeLimits] of the client early; the client checks the sizes again.
 * An exception of the transport becomes [AcmeError.Transport]; its message never reaches the caller. A
 * [kotlinx.coroutines.CancellationException] cancels the operation.
 *
 * @since 1.0.0
 */
public fun interface AcmeTransport {
    /**
     * Whether the client accepts `http` URLs besides `https`, for a test server only. False by default: RFC 8555
     * requires HTTPS for every resource.
     *
     * @since 1.0.0
     */
    public val isPlainHttpAllowed: Boolean get() = false

    /**
     * Sends [request] and returns the response of the server.
     *
     * @param request the request.
     * @return the response, also for a status of 400 and above.
     * @since 1.0.0
     */
    public suspend fun exchange(request: AcmeRequest): AcmeResponse
}
