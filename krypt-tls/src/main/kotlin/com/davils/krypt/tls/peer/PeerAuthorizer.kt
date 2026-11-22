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

package com.davils.krypt.tls.peer

/**
 * Decides whether a peer whose certificates krypt validated may connect, such as by its SPIFFE id.
 *
 * The authorizer runs inside the handshake, on the thread of JSSE, after the path, the revocation, the pins and the
 * transparency of the peer were checked; [PeerPolicy] is the built-in implementation. An authorizer that fails is
 * contained and counts as [Authorization.Denied]. An authorizer that really suspends blocks the handshake while it
 * waits; krypt sets no timeout, so such an authorizer bounds its own time, such as with `withTimeout`, and must never
 * resume on a single-threaded dispatcher whose thread runs the handshake, or the handshake deadlocks.
 *
 * A session that JSSE resumes skips the authorizer, as it skips every check of the certificates: a decision that
 * changed after the full handshake applies only once the session expired, after
 * [com.davils.krypt.tls.TlsConfiguration.sessionTimeout], or [com.davils.krypt.tls.TlsContext.rotate] invalidated
 * it. An application whose decisions change at runtime keeps the session timeout short or rotates.
 *
 * @since 1.0.0
 */
public fun interface PeerAuthorizer {
    /**
     * Decides about [peer].
     *
     * @param peer the validated identity.
     * @return whether the peer may connect.
     * @since 1.0.0
     */
    public suspend fun authorize(peer: PeerIdentity): Authorization
}
