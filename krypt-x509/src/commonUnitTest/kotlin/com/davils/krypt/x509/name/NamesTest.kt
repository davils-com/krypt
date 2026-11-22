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

package com.davils.krypt.x509.name

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import com.davils.krypt.x509.internal.NameCodec.readName
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import kotlinx.io.bytestring.ByteString

private const val PARTS: Int = 5
private const val DOMAIN_INDEX: Int = 3
private const val IPV6_BYTES: Int = 16
private const val ESCAPED: String = """CN=\ a\,b\+c\=\"d\\e\<f\>g\;h #\01\ """

private fun tagOf(name: DistinguishedName): Tag {
    val attribute = name.names
        .single()
        .attributes
        .single()
    return attribute.tag
}

private const val ORGANIZATION: String = "Davils GmbH"
private const val NAME: String = "krypt"
private const val MAXIMUM: Int = 64

class NamesTest : FunSpec({
    test("a name is built most significant first and written by RFC 4514") {
        val name = distinguishedName {
            country("DE")
            organization(ORGANIZATION)
            organizationalUnit("R&D")
            domainComponent("example")
            multiValued(listOf(AttributeTypes.CommonName to NAME, AttributeTypes.UserId to "42"))
        }
        name.rfc4514() shouldBe "CN=krypt+UID=42,DC=example,OU=R&D,O=Davils GmbH,C=DE"
        name.commonName shouldBe NAME
        name.valuesOf(AttributeTypes.Country) shouldBe listOf("DE")
        name.names.size shouldBe PARTS
        name.isEmpty shouldBe false
        name.toString() shouldContain "CN=krypt"
        name.names
            .first()
            .attributes
            .single()
            .tag shouldBe Tag.PrintableString
        name.names[DOMAIN_INDEX]
            .attributes
            .single()
            .tag shouldBe Tag.Ia5String
        name.names[1]
            .attributes
            .single()
            .tag shouldBe Tag.Utf8String
        DistinguishedName.Empty.isEmpty shouldBe true
        DistinguishedName.Empty.commonName shouldBe null
        DistinguishedName.Empty.rfc4514() shouldBe ""
    }

    test("special characters are escaped and controls shown in hex") {
        val name = distinguishedName { commonName(" a,b+c=\"d\\e<f>g;h #\u0001 ") }
        name.rfc4514() shouldBe ESCAPED
        distinguishedName { commonName("#hash") }.rfc4514() shouldBe "CN=\\#hash"
        name.toString() shouldNotContain "\u0001"
    }

    test("names compare by RFC 5280, ignoring case and white space") {
        val first = distinguishedName {
            organization("Davils   GmbH")
            commonName(NAME)
        }
        val second = distinguishedName {
            organization(" davils gmbh ")
            commonName("KRYPT")
        }
        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
        first shouldNotBe distinguishedName { commonName(NAME) }
        first shouldNotBe Any()
        val prefix = distinguishedName { organization(ORGANIZATION) }
        prefix.isPrefixOf(first) shouldBe true
        first.isPrefixOf(prefix) shouldBe false
        distinguishedName { organization("Other") }.isPrefixOf(first) shouldBe false
        val multi = distinguishedName {
            multiValued(
                listOf(AttributeTypes.UserId to "1", AttributeTypes.CommonName to "a"),
            )
        }
        val reordered = distinguishedName {
            multiValued(
                listOf(AttributeTypes.CommonName to "A", AttributeTypes.UserId to "1"),
            )
        }
        multi shouldBe reordered
        multi.names.single() shouldBe reordered.names.single()
        multi.names.single().hashCode() shouldBe reordered.names.single().hashCode()
        multi.names.single() shouldNotBe Any()
        multi.names.single().toString() shouldBe "CN=a+UID=1"
    }

    test("values that are no strings are shown and compared by their encoding") {
        val encoded = Der.encode {
            sequence {
                setOf {
                    sequence {
                        objectIdentifier(ObjectIdentifier.of("1.2.3.4"))
                        integer(7L)
                    }
                }
            }
        }
        val name = checkNotNull(Der.decodeOrNull(encoded) { readName(MAXIMUM) })
        name.rfc4514() shouldBe "1.2.3.4=#020107"
        val attribute = name.names
            .single()
            .attributes
            .single()
        attribute.text shouldBe null
        val again = checkNotNull(Der.decodeOrNull(encoded) { readName(MAXIMUM) })
        attribute shouldBe again.names
            .single()
            .attributes
            .single()
        attribute shouldNotBe Any()
        attribute.hashCode() shouldBe attribute.hashCode()
        attribute.toString() shouldBe "1.2.3.4=#020107"
    }

    test("a name refuses empty sets and too many parts") {
        val empty = Der.encode { sequence { setOf {} } }
        Der.decodeOrNull(empty) { readName(MAXIMUM) } shouldBe null
        val many = Der.encode {
            sequence {
                repeat(
                    3,
                ) {
                    setOf {
                        sequence {
                            objectIdentifier(AttributeTypes.CommonName)
                            utf8String("x")
                        }
                    }
                }
            }
        }
        Der.decodeOrNull(many) { readName(2) } shouldBe null
        val wide = Der.encode {
            sequence {
                setOf {
                    repeat(
                        3,
                    ) { index ->
                        sequence {
                            objectIdentifier(AttributeTypes.CommonName)
                            utf8String("$index")
                        }
                    }
                }
            }
        }
        Der.decodeOrNull(wide) { readName(2) } shouldBe null
        shouldThrow<IllegalArgumentException> { distinguishedName { country("Germany") } }
        shouldThrow<IllegalArgumentException> { distinguishedName { commonName("") } }
        shouldThrow<IllegalArgumentException> { distinguishedName { multiValued(emptyList()) } }
        tagOf(distinguishedName { attribute(AttributeTypes.SerialNumber, "ÄÖÜ") }) shouldBe Tag.Utf8String
        tagOf(distinguishedName { attribute(AttributeTypes.EmailAddress, "ä@example.org") }) shouldBe Tag.Utf8String
    }

    test("general names compare, show and parse addresses") {
        GeneralName.Dns("Example.COM") shouldBe GeneralName.Dns("example.com")
        GeneralName.Dns("a").hashCode() shouldBe GeneralName.Dns("A").hashCode()
        GeneralName.Dns("a").toString() shouldBe "DNS:a"
        GeneralName.Email("Ada@Example.org") shouldBe GeneralName.Email("Ada@example.ORG")
        GeneralName.Email("ada@x") shouldNotBe GeneralName.Email("ADA@x")
        GeneralName.Email("a@b").toString() shouldBe "email:a@b"
        GeneralName.Email("a@b").hashCode() shouldBe GeneralName.Email("a@B").hashCode()
        GeneralName.Uri("https://a").toString() shouldBe "URI:https://a"
        GeneralName.Uri("x") shouldBe GeneralName.Uri("x")
        GeneralName.Uri("x").hashCode() shouldBe "x".hashCode()
        val directory = GeneralName.Directory(distinguishedName { commonName(NAME) })
        directory shouldBe GeneralName.Directory(distinguishedName { commonName("KRYPT") })
        directory.hashCode() shouldBe directory.name.hashCode()
        directory.toString() shouldBe "DirName:CN=krypt"
        val id = GeneralName.RegisteredId(AttributeTypes.CommonName)
        id shouldBe GeneralName.RegisteredId(AttributeTypes.CommonName)
        id.hashCode() shouldBe AttributeTypes.CommonName.hashCode()
        id.toString() shouldBe "RID:2.5.4.3"
        listOf<GeneralName>(
            GeneralName.Dns("a"),
            GeneralName.Email("a"),
            GeneralName.Uri("a"),
            directory,
            id,
        ).forEach { name ->
            name shouldNotBe Any()
        }
    }

    test("IP addresses are read and shown in their canonical forms") {
        val cases = mapOf(
            "192.0.2.1" to "IP:192.0.2.1",
            "2001:db8::1" to "IP:2001:db8::1",
            "2001:DB8:0:0:1:0:0:1" to "IP:2001:db8::1:0:0:1",
            "::" to "IP:::",
            "::1" to "IP:::1",
            "1::" to "IP:1::",
            "1:0:2:0:0:3:0:4" to "IP:1:0:2::3:0:4",
            "1:2:3:4:5:6:7:8" to "IP:1:2:3:4:5:6:7:8",
            "0:1:0:1:0:1:0:1" to "IP:0:1:0:1:0:1:0:1",
        )
        cases.forEach { (text, shown) ->
            checkNotNull(
                GeneralName.IpAddress.parseOrNull(text),
            ).toString() shouldBe shown
        }
        listOf(
            "256.0.0.1",
            "01.2.3.4",
            "1.2.3",
            "a.b.c.d",
            "1:2:3:4:5:6:7:8:9",
            "1::2::3",
            "12345::",
            "g::",
            ":1",
            "",
            "1:2:3:4:5:6:7",
        ).forEach { text -> GeneralName.IpAddress.parseOrNull(text) shouldBe null }
        val masked = GeneralName.IpAddress(ByteString(10, 0, 0, 0, -1, 0, 0, 0))
        masked.toString() shouldBe "IP:10.0.0.0/255.0.0.0"
        val v6 = checkNotNull(GeneralName.IpAddress.parseOrNull("2001:db8::"))
        GeneralName.IpAddress(ByteString(v6.bytes.toByteArray() + ByteArray(IPV6_BYTES) { -1 })).toString() shouldBe
            "IP:2001:db8::/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        masked shouldBe GeneralName.IpAddress(masked.bytes)
        masked shouldNotBe Any()
        masked.hashCode() shouldBe masked.bytes.hashCode()
        shouldThrow<IllegalArgumentException> { GeneralName.IpAddress(ByteString(1, 2)) }
    }
})
