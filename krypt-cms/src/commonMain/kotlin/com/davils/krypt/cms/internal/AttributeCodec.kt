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

package com.davils.krypt.cms.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerReader
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.cms.Attribute
import kotlinx.io.bytestring.ByteString

internal object AttributeCodec {
    fun DerReader.readAttributeSet(tag: Tag, maximum: Int, isSorted: Boolean): AttributeSet {
        val element = readElement(tag)
        val attributes = setChildren(element, maximum, isSorted).map { item ->
            item.parse(Tag.Sequence) { readAttribute(maximum, isSorted) }
        }
        if (attributes.isEmpty()) malformed("a set of attributes with an attribute")
        return AttributeSet(attributes = attributes, element = element)
    }

    fun DerWriter.writeAttributes(tag: Tag, attributes: List<Attribute>) {
        sortedSet(tag, attributes.map { attribute -> encode(attribute) })
    }

    fun encodeSet(attributes: List<Attribute>): ByteString = Der.encode { writeAttributes(Tag.Set, attributes) }

    fun encode(attribute: Attribute): ByteString = Der.encode {
        sequence {
            objectIdentifier(attribute.type)
            sortedSet(Tag.Set, attribute.values)
        }
    }

    fun single(set: AttributeSet, type: ObjectIdentifier): ByteString? {
        val attribute = set.attributes.firstOrNull { found -> found.type == type } ?: return null
        if (attribute.values.size != 1) malformed("one value of attribute ${type.dotted}")
        return attribute.values.first()
    }

    private fun DerReader.readAttribute(maximum: Int, isSorted: Boolean): Attribute {
        val type = readObjectIdentifier()
        val values = readSetElements(Tag.Set, maximum, isSorted).map { value -> value.encoded }
        if (values.isEmpty()) malformed("an attribute with a value")
        return Attribute(type, values)
    }
}
