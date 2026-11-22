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

package com.davils.krypt.x509.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerElement
import com.davils.krypt.asn1.DerException
import com.davils.krypt.asn1.DerFailure
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.asn1.TagClass
import com.davils.krypt.x509.name.AttributeTypes
import com.davils.krypt.x509.name.AttributeValue
import com.davils.krypt.x509.name.DistinguishedName
import com.davils.krypt.x509.name.GeneralName
import com.davils.krypt.x509.name.RelativeName

private const val OTHER_NAME: Int = 0
private const val EMAIL: Int = 1
private const val DNS: Int = 2
private const val X400: Int = 3
private const val DIRECTORY: Int = 4
private const val EDI_PARTY: Int = 5
private const val URI: Int = 6
private const val IP_ADDRESS: Int = 7
private const val REGISTERED_ID: Int = 8
private const val ASCII_LIMIT: Int = 0x80

internal object NameCodec {
    private val READERS: Map<Int, (DerElement, Int) -> GeneralName> = mapOf(
        OTHER_NAME to { element, _ -> GeneralName.Other(OtherNameParts(element.encoded)) },
        X400 to { element, _ -> GeneralName.Other(OtherNameParts(element.encoded)) },
        EDI_PARTY to { element, _ -> GeneralName.Other(OtherNameParts(element.encoded)) },
        EMAIL to { element, _ -> GeneralName.Email(ia5(element)) },
        DNS to { element, _ -> GeneralName.Dns(ia5(element)) },
        URI to { element, _ -> GeneralName.Uri(ia5(element)) },
        IP_ADDRESS to { element, _ -> ipAddress(element) },
        DIRECTORY to { element, maximum -> GeneralName.Directory(directory(element, maximum)) },
        REGISTERED_ID to { element, _ -> registeredId(element) },
    )

    private val PRINTABLE_EXTRA: Set<Char> = setOf(' ', '\'', '(', ')', '+', ',', '-', '.', '/', ':', '=', '?')

    fun DerReader.readName(maximum: Int): DistinguishedName {
        val element = readElement(Tag.Sequence)
        val inner = element.reader()
        val names = mutableListOf<RelativeName>()
        while (!inner.isExhausted) {
            if (names.size >= maximum) inner.refuse(DerFailure.LimitExceeded, "at most $maximum relative names")
            names += inner.readSet { readRelativeName(maximum) }
        }
        return DistinguishedName(NameParts(names = names, encoded = element.encoded))
    }

    fun build(names: List<List<Pair<ObjectIdentifier, String>>>): DistinguishedName {
        val encoded = Der.encode {
            sequence {
                names.forEach { attributes ->
                    setOf { attributes.forEach { (type, value) -> writeAttribute(type, value) } }
                }
            }
        }
        return checkNotNull(Der.decodeOrNull(encoded) { readName(Int.MAX_VALUE) })
    }

    fun DerReader.readGeneralNames(maximum: Int): List<GeneralName> = readSequence {
        val names = mutableListOf<GeneralName>()
        while (!isExhausted) {
            if (names.size >= maximum) refuse(DerFailure.LimitExceeded, "at most $maximum general names")
            names += readGeneralName(maximum)
        }
        if (names.isEmpty()) refuse(DerFailure.InvalidValue, "at least one general name")
        names
    }

    fun DerWriter.writeGeneralNames(names: List<GeneralName>) {
        sequence { names.forEach { name -> writeGeneralName(name) } }
    }

    fun DerReader.readGeneralName(maximum: Int): GeneralName {
        val element = readElement()
        val tag = element.tag
        val isContext = tag.tagClass == TagClass.ContextSpecific
        val reader = READERS[tag.number].takeIf { isContext } ?: refuse(DerFailure.InvalidValue, "a general name")
        return reader(element, maximum)
    }

    fun DerWriter.writeGeneralName(name: GeneralName) {
        when (name) {
            is GeneralName.Dns -> ia5String(name.name, Tag.context(number = DNS, isConstructed = false))

            is GeneralName.Email -> ia5String(name.address, Tag.context(number = EMAIL, isConstructed = false))

            is GeneralName.Uri -> ia5String(name.uri, Tag.context(number = URI, isConstructed = false))

            is GeneralName.IpAddress -> octetString(name.bytes, Tag.context(number = IP_ADDRESS, isConstructed = false))

            is GeneralName.Directory -> explicit(DIRECTORY) { raw(name.name.encoded) }

            is GeneralName.RegisteredId -> objectIdentifier(
                name.id,
                Tag.context(number = REGISTERED_ID, isConstructed = false),
            )

            is GeneralName.Other -> raw(name.encoded)
        }
    }

    private fun DerReader.readRelativeName(maximum: Int): RelativeName {
        val attributes = mutableListOf<AttributeValue>()
        while (!isExhausted) {
            if (attributes.size >= maximum) refuse(DerFailure.LimitExceeded, "at most $maximum attributes")
            attributes += readSequence {
                val type = readObjectIdentifier()
                val value = readElement()
                val text = Der.decodeOrNull(value.encoded) { readText() }
                AttributeValue(AttributeParts(type = type, text = text, tag = value.tag, encoded = value.encoded))
            }
        }
        if (attributes.isEmpty()) refuse(DerFailure.InvalidValue, "at least one attribute")
        return RelativeName(RelativeNameParts(attributes))
    }

    private fun DerWriter.writeAttribute(type: ObjectIdentifier, value: String) {
        sequence {
            objectIdentifier(type)
            val isPrintable = type in AttributeTypes.PRINTABLE_TYPES && value.all { char -> isPrintable(char) }
            val isIa5 = type in AttributeTypes.IA5_TYPES && value.all { char -> char.code < ASCII_LIMIT }
            val kind = listOf(isPrintable, isIa5).indexOf(true) + 1
            val writers = listOf({ utf8String(value) }, { printableString(value) }, { ia5String(value) })
            writers[kind]()
        }
    }

    private fun isPrintable(char: Char): Boolean {
        val isAlphanumeric = char in 'A'..'Z' || char in 'a'..'z' || char in '0'..'9'
        return isAlphanumeric || char in PRINTABLE_EXTRA
    }

    private fun ia5(element: DerElement): String {
        val bytes = element.content.toByteArray()
        val isAscii = bytes.all { byte -> byte >= 0 }
        if (!isAscii) throw DerException(DerFailure.InvalidValue, "an IA5String")
        return bytes.decodeToString()
    }

    private fun ipAddress(element: DerElement): GeneralName {
        val isValid = element.content.size in IpAddresses.SIZES
        if (!isValid) throw DerException(DerFailure.InvalidValue, "an IP address of 4 or 16 bytes")
        return GeneralName.IpAddress(element.content)
    }

    private fun directory(element: DerElement, maximum: Int): DistinguishedName {
        val isConstructed = element.tag.isConstructed
        if (!isConstructed) throw DerException(DerFailure.InvalidValue, "an explicit name")
        val inner = element.reader()
        val name = inner.readName(maximum)
        if (!inner.isExhausted) inner.refuse(DerFailure.InvalidValue, "a single name")
        return name
    }

    private fun registeredId(element: DerElement): GeneralName {
        val id = ObjectIdentifier.decodeOrNull(element.content)
            ?: throw DerException(DerFailure.InvalidValue, "an object identifier")
        return GeneralName.RegisteredId(id)
    }
}
