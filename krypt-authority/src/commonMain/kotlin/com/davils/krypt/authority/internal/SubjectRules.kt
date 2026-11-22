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

package com.davils.krypt.authority.internal

import com.davils.krypt.authority.policy.IssuancePolicy
import com.davils.krypt.x509.name.AttributeTypes
import com.davils.krypt.x509.name.AttributeValue
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.GeneralName

private const val SCHEME: String = "://"
private const val ADDRESS_PREFIX: String = "IP:"

internal object SubjectRules {
    fun isPermitted(subject: DistinguishedName, names: List<GeneralName>, policy: IssuancePolicy): Boolean {
        val attributes = subject.names.flatMap { name -> name.attributes }
        val areTypesAllowed = attributes.all { attribute -> isAllowed(attribute, policy) }
        val areFixed = attributes.all { attribute -> isFixed(attribute, policy) }
        val commonNames = attributes.filter { attribute -> attribute.type == AttributeTypes.CommonName }
        val areCommonNamesPermitted = commonNames.all { attribute ->
            isCommonNamePermitted(text = attribute.text, names = names, policy = policy)
        }
        return areTypesAllowed && areFixed && areCommonNamesPermitted
    }

    private fun isAllowed(attribute: AttributeValue, policy: IssuancePolicy): Boolean =
        attribute.type in policy.subjectAttributes && attribute.type != AttributeTypes.EmailAddress

    private fun isFixed(attribute: AttributeValue, policy: IssuancePolicy): Boolean {
        val fixed = policy.fixedAttributes[attribute.type]
        return fixed == null || attribute.text == fixed
    }

    private fun isCommonNamePermitted(text: String?, names: List<GeneralName>, policy: IssuancePolicy): Boolean {
        val value = text ?: return false
        val isAlternative = names.any { name -> textOf(name)?.equals(value, ignoreCase = true) == true }
        val isAlone = names.isEmpty() && isNamePermitted(value, policy)
        return isAlternative || isAlone
    }

    private fun isNamePermitted(value: String, policy: IssuancePolicy): Boolean {
        val isDnsLike = '.' in value && value.none { char -> char.isWhitespace() }
        val candidates = listOf(
            GeneralName.Uri(value).takeIf { SCHEME in value },
            GeneralName.Email(value).takeIf { '@' in value },
            GeneralName.Dns(value).takeIf { isDnsLike },
        )
        val candidate = candidates.firstOrNull { found -> found != null }
        return candidate == null || NameRules.isPermitted(candidate, policy)
    }

    private fun textOf(name: GeneralName): String? = when (name) {
        is GeneralName.Dns -> name.name
        is GeneralName.Email -> name.address
        is GeneralName.Uri -> name.uri
        is GeneralName.IpAddress -> name.toString().removePrefix(ADDRESS_PREFIX)
        is GeneralName.Directory, is GeneralName.RegisteredId, is GeneralName.Other -> null
    }
}
