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

import com.davils.kore.core.annotation.DavilsDsl
import com.davils.kore.core.dsl.ValidatingBuilder
import com.davils.krypt.asn1.ObjectIdentifier

/**
 * Builds a [PeerPolicy]; without any rule, every validated peer is granted.
 *
 * @since 1.0.0
 */
@DavilsDsl
public class PeerPolicyBuilder internal constructor() : ValidatingBuilder<PeerPolicy>() {
    override val subject: String get() = "peerPolicy"

    internal val uris: MutableList<String> = mutableListOf()

    internal val uriPrefixes: MutableList<String> = mutableListOf()

    internal val dnsNames: MutableList<String> = mutableListOf()

    internal val dnsDomains: MutableList<String> = mutableListOf()

    internal val emails: MutableList<String> = mutableListOf()

    internal val emailDomains: MutableList<String> = mutableListOf()

    internal val purposes: MutableList<ObjectIdentifier> = mutableListOf()

    internal var predicate: (suspend (PeerIdentity) -> Boolean)? = null

    /**
     * Allows a URI exactly, such as the SPIFFE id `spiffe://example.org/ns/prod/sa/api`.
     *
     * @param uri the URI.
     * @since 1.0.0
     */
    public fun uri(uri: String) {
        checkOpen()
        uris += uri
    }

    /**
     * Allows every URI that starts with [prefix], such as the trust domain `spiffe://example.org/` of SPIFFE. The
     * prefix must name a scheme and end with a slash, so that `spiffe://example.org.evil/` never matches.
     *
     * @param prefix the prefix.
     * @since 1.0.0
     */
    public fun uriPrefix(prefix: String) {
        checkOpen()
        uriPrefixes += prefix
    }

    /**
     * Allows a DNS name exactly, without regard to case; a wildcard in a certificate is no exact name.
     *
     * @param name the DNS name.
     * @since 1.0.0
     */
    public fun dns(name: String) {
        checkOpen()
        dnsNames += name
    }

    /**
     * Allows every DNS name below [domain], such as `api.example.org` below `example.org`, but not the domain itself.
     *
     * @param domain the domain.
     * @since 1.0.0
     */
    public fun dnsDomain(domain: String) {
        checkOpen()
        dnsDomains += domain
    }

    /**
     * Allows an email address exactly, its domain without regard to case.
     *
     * @param address the address.
     * @since 1.0.0
     */
    public fun email(address: String) {
        checkOpen()
        emails += address
    }

    /**
     * Allows every email address of [domain].
     *
     * @param domain the domain.
     * @since 1.0.0
     */
    public fun emailDomain(domain: String) {
        checkOpen()
        emailDomains += domain
    }

    /**
     * Requires the extended key usage of the peer to list [purpose].
     *
     * @param purpose the key purpose, such as [com.davils.krypt.x509.extension.KeyPurposes.ClientAuth].
     * @since 1.0.0
     */
    public fun purpose(purpose: ObjectIdentifier) {
        checkOpen()
        purposes += purpose
    }

    /**
     * Requires [predicate] to accept the peer; a predicate that fails denies the peer.
     *
     * @param predicate the check of the application.
     * @since 1.0.0
     */
    public fun require(predicate: suspend (PeerIdentity) -> Boolean) {
        checkOpen()
        this.predicate = predicate
    }

    override fun assemble(): PeerPolicy = PeerPolicy(this)
}
