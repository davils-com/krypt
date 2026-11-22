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

import com.davils.kore.core.failure.attempted
import com.davils.kore.core.validation.Validatable
import com.davils.kore.core.validation.ValidationScope
import com.davils.kore.core.validation.atMost
import com.davils.kore.core.validation.validateOrThrow
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.x509.name.GeneralName
import kotlin.reflect.KProperty

private const val SUBJECT: String = "peerPolicy"
private const val SCHEME: String = "://"

/**
 * The built-in [PeerAuthorizer], built by [PeerPolicyBuilder]: allowlists of subject alternative names, required
 * purposes and a predicate of the application.
 *
 * A peer is granted if, first, one of its names matches one of the name rules, when there are any; second, its
 * extended key usage lists every required purpose; and third, the predicate, if any, accepts it. URIs compare exactly
 * and by prefix, such as the trust domain `spiffe://example.org/` of SPIFFE; DNS names compare without regard to case
 * and by suffix below a domain; email addresses compare with the domain without regard to case and by domain.
 *
 * Safe to share between threads.
 *
 * @since 1.0.0
 */
public class PeerPolicy internal constructor(builder: PeerPolicyBuilder) : PeerAuthorizer, Validatable {
    /**
     * The URIs allowed exactly.
     *
     * @since 1.0.0
     */
    public val uris: List<String> = builder.uris.toList()

    /**
     * The prefixes of allowed URIs, each with a scheme and ending with a slash.
     *
     * @since 1.0.0
     */
    public val uriPrefixes: List<String> = builder.uriPrefixes.toList()

    /**
     * The DNS names allowed exactly, in lower case.
     *
     * @since 1.0.0
     */
    public val dnsNames: List<String> = builder.dnsNames.map { name -> name.lowercase() }

    /**
     * The domains below which every DNS name is allowed, in lower case.
     *
     * @since 1.0.0
     */
    public val dnsDomains: List<String> = builder.dnsDomains.map { name -> name.lowercase() }

    /**
     * The email addresses allowed exactly.
     *
     * @since 1.0.0
     */
    public val emails: List<String> = builder.emails.toList()

    /**
     * The domains of which every email address is allowed, in lower case.
     *
     * @since 1.0.0
     */
    public val emailDomains: List<String> = builder.emailDomains.map { name -> name.lowercase() }

    /**
     * The purposes the extended key usage of the peer must list.
     *
     * @since 1.0.0
     */
    public val purposes: List<ObjectIdentifier> = builder.purposes.toList()

    private val predicate: (suspend (PeerIdentity) -> Boolean)? = builder.predicate

    private val ruleCount: Int
        get() = uris.size + uriPrefixes.size + dnsNames.size + dnsDomains.size + emails.size + emailDomains.size

    init {
        validateOrThrow(SUBJECT)
    }

    override suspend fun authorize(peer: PeerIdentity): Authorization {
        val isNamed = ruleCount == 0 || isAllowed(peer)
        val isPurposeful = purposes.all { purpose -> purpose in peer.purposes }
        val isAccepted = isNamed && isPurposeful && isAcceptedByPredicate(peer)
        return DECISIONS[isAccepted.compareTo(false)]
    }

    override fun ValidationScope.validate() {
        texts(::uris, uris)
        texts(::uriPrefixes, uriPrefixes)
        texts(::dnsNames, dnsNames)
        texts(::dnsDomains, dnsDomains)
        texts(::emails, emails)
        texts(::emailDomains, emailDomains)
        atMost(property = ::purposes, value = purposes.size, maximum = HARD_MAXIMUM_RULES)
        each(::uriPrefixes, uriPrefixes) { prefix ->
            val isScoped = prefix.contains(SCHEME) && prefix.endsWith('/')
            if (!isScoped) fail("A URI prefix has a scheme and ends with a slash")
        }
    }

    /**
     * Shows the number of rules.
     *
     * @return the policy as text.
     * @since 1.0.0
     */
    override fun toString(): String =
        "PeerPolicy(rules=$ruleCount, purposes=${purposes.size}, predicate=${predicate != null})"

    private suspend fun isAcceptedByPredicate(peer: PeerIdentity): Boolean {
        val accepts = predicate ?: return true
        return attempted { accepts(peer) }.getOrDefault(false)
    }

    private fun isAllowed(peer: PeerIdentity): Boolean {
        val names = peer.names
        val isUriAllowed = peer.uris.any { uri -> isAllowedUri(uri) }
        val isDnsAllowed = names.filterIsInstance<GeneralName.Dns>().any { name -> isAllowedDns(name.name) }
        val isEmailAllowed = names.filterIsInstance<GeneralName.Email>().any { name -> isAllowedEmail(name) }
        return isUriAllowed || isDnsAllowed || isEmailAllowed
    }

    private fun isAllowedUri(uri: String): Boolean = uri in uris || uriPrefixes.any { prefix -> uri.startsWith(prefix) }

    private fun isAllowedDns(presented: String): Boolean {
        val name = presented.lowercase().removeSuffix(".")
        return name in dnsNames || dnsDomains.any { domain -> name.endsWith(".$domain") }
    }

    private fun isAllowedEmail(name: GeneralName.Email): Boolean {
        val domain = name.address.substringAfterLast('@', "").lowercase()
        return emails.any { address -> GeneralName.Email(address) == name } || domain in emailDomains
    }

    private fun ValidationScope.texts(property: KProperty<*>, values: List<String>) {
        atMost(property = property, value = values.size, maximum = HARD_MAXIMUM_RULES)
        each(property, values) { value ->
            val isSized = value.isNotBlank() && value.length <= HARD_MAXIMUM_LENGTH
            if (!isSized) fail("A rule has 1 to $HARD_MAXIMUM_LENGTH characters")
        }
    }

    /**
     * The bounds of a policy.
     *
     * @since 1.0.0
     */
    public companion object {
        private val DECISIONS: List<Authorization> = listOf(Authorization.Denied, Authorization.Granted)

        /**
         * The most rules of one kind.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_RULES: Int = 1_024

        /**
         * The longest rule.
         *
         * @since 1.0.0
         */
        public const val HARD_MAXIMUM_LENGTH: Int = 2_048
    }
}
