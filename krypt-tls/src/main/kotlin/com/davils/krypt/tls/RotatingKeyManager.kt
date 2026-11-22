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

@file:OptIn(ExperimentalAtomicApi::class)

package com.davils.krypt.tls

import com.davils.krypt.keystore.Identity
import com.davils.krypt.primitive.Crypto
import com.davils.krypt.tls.internal.IdentityRing
import com.davils.krypt.tls.internal.KeyEntry
import com.davils.krypt.tls.internal.Sessions
import com.davils.krypt.x509.path.ServiceIdentity
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSession
import javax.net.ssl.X509ExtendedKeyManager
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * The key manager of krypt: it offers one or more [Identity] of krypt-keystore to JSSE and reads them atomically, so
 * [rotate] changes the identity of every later handshake without a new SSLContext, while a connection already
 * established keeps its own.
 *
 * A server chooses among the identities whose key fits the signature schemes the client accepts, first the one whose
 * certificate names the host the client asked for by server name indication (RFC 6066), matched by RFC 9525, and
 * otherwise the first. A client chooses among the identities whose key fits what the server accepts, first one whose
 * chain was issued by an authority the server names, and otherwise the first.
 *
 * The private keys stay in their provider: a key in a hardware security module is handed to JSSE as its handle.
 *
 * Safe to share between threads.
 *
 * @since 1.0.0
 */
public class RotatingKeyManager internal constructor(private val crypto: Crypto, identities: List<Identity>) :
    X509ExtendedKeyManager() {
    private val lock = Any()

    private val rings = AtomicReference(
        listOf(IdentityRing.of(crypto = crypto, generation = 0L, identities = identities)),
    )

    /**
     * The identities of every new handshake.
     *
     * @since 1.0.0
     */
    public val identities: List<Identity> get() = rings.load().first().identities

    /**
     * Replaces the identities for every later handshake; a handshake in progress finishes with the identity it chose.
     *
     * @param identities the new identities, the default first.
     * @throws IllegalArgumentException if there are more than [TlsConfiguration.HARD_MAXIMUM_IDENTITIES] identities.
     * @throws IllegalStateException if the key of an identity was destroyed.
     * @since 1.0.0
     */
    public fun rotate(identities: List<Identity>) {
        require(identities.size <= TlsConfiguration.HARD_MAXIMUM_IDENTITIES) {
            "At most ${TlsConfiguration.HARD_MAXIMUM_IDENTITIES} identities are offered"
        }
        synchronized(lock) {
            val current = rings.load().first()
            val ring = IdentityRing.of(crypto = crypto, generation = current.generation + 1, identities = identities)
            rings.store(listOf(ring, current))
        }
    }

    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? =
        serverAlias(keyType, Sessions.of(socket))

    override fun chooseEngineServerAlias(
        keyType: String?,
        issuers: Array<out Principal>?,
        engine: SSLEngine?,
    ): String? = serverAlias(keyType, Sessions.of(engine))

    override fun chooseClientAlias(
        keyTypes: Array<out String>?,
        issuers: Array<out Principal>?,
        socket: Socket?,
    ): String? = clientAlias(keyTypes, issuers)

    override fun chooseEngineClientAlias(
        keyTypes: Array<out String>?,
        issuers: Array<out Principal>?,
        engine: SSLEngine?,
    ): String? = clientAlias(keyTypes, issuers)

    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = aliases(keyType)

    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = aliases(keyType)

    override fun getCertificateChain(alias: String?): Array<X509Certificate>? {
        val entry = find(alias) ?: return null
        return entry.chain.toTypedArray()
    }

    override fun getPrivateKey(alias: String?): PrivateKey? = find(alias)?.key

    /**
     * Shows the number of identities.
     *
     * @return the manager as text.
     * @since 1.0.0
     */
    override fun toString(): String = "RotatingKeyManager(${identities.size} identities)"

    private fun serverAlias(keyType: String?, session: SSLSession?): String? {
        val host = Sessions.requestedHost(session)
        val candidates = fitting(listOfNotNull(keyType))
        val preferred = candidates.sortedBy { entry -> !isNamed(entry, host) }
        return preferred.firstOrNull()?.alias
    }

    private fun clientAlias(keyTypes: Array<out String>?, issuers: Array<out Principal>?): String? {
        val accepted = issuers.orEmpty().toSet()
        val candidates = fitting(keyTypes.orEmpty().toList())
        val preferred = candidates.sortedBy { entry -> !isIssued(entry, accepted) }
        return preferred.firstOrNull()?.alias
    }

    private fun aliases(keyType: String?): Array<String>? {
        val found = fitting(listOfNotNull(keyType)).map { entry -> entry.alias }
        return found.toTypedArray().takeIf { found.isNotEmpty() }
    }

    private fun fitting(keyTypes: List<String>): List<KeyEntry> {
        val current = rings.load().first()
        return current.entries.filter { entry -> keyTypes.any { keyType -> keyType in entry.keyTypes } }
    }

    private fun isNamed(entry: KeyEntry, host: String?): Boolean =
        host?.let { name -> ServiceIdentity.matches(entry.identity.certificate, name) } == true

    private fun isIssued(entry: KeyEntry, accepted: Set<Principal>): Boolean =
        entry.chain.any { certificate -> certificate.issuerX500Principal in accepted }

    private fun find(alias: String?): KeyEntry? {
        val entries = rings.load().flatMap { ring -> ring.entries }
        return entries.firstOrNull { entry -> entry.alias == alias }
    }
}
