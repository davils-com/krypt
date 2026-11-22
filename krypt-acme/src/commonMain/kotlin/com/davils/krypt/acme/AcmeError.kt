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
 * A failure the client found itself, without a problem document of the server.
 *
 * @since 1.0.0
 */
public enum class AcmeError : AcmeFailure {
    /**
     * The transport threw; its exception is not passed on.
     *
     * @since 1.0.0
     */
    Transport,

    /**
     * A response breaks an [AcmeLimits] limit.
     *
     * @since 1.0.0
     */
    LimitExceeded,

    /**
     * A response is not what RFC 8555 prescribes: broken JSON, a missing or mistyped member, an unknown status, a
     * bad nonce, token, time or header field.
     *
     * @since 1.0.0
     */
    Malformed,

    /**
     * The server named a URL that is not absolute `https`, or `http` where the transport allows it.
     *
     * @since 1.0.0
     */
    InsecureUrl,

    /**
     * The server answered with a status the operation does not expect and without a problem document.
     *
     * @since 1.0.0
     */
    UnexpectedStatus,

    /**
     * The server does not offer what the operation needs, such as key rollover or renewal information, or the
     * certificate lacks what renewal information needs.
     *
     * @since 1.0.0
     */
    Unsupported,

    /**
     * A polling helper gave up before the resource left its pending state.
     *
     * @since 1.0.0
     */
    PollsExhausted,
}
