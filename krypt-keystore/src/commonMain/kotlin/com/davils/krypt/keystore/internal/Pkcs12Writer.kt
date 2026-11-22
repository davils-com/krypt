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

package com.davils.krypt.keystore.internal

import com.davils.krypt.asn1.Der
import com.davils.krypt.asn1.DerWriter
import com.davils.krypt.asn1.ObjectIdentifier
import com.davils.krypt.asn1.Tag
import kotlinx.io.bytestring.ByteString

private const val VERSION: Long = 3L
private const val BYTE_BITS: Int = 8
private const val MAC_KEY_BYTES: Long = 32L

internal object Pkcs12Writer {
    fun bag(type: ObjectIdentifier, value: ByteString, attributes: BagAttributes): ByteString = Der.encode {
        sequence {
            objectIdentifier(type)
            explicit(0) { raw(value) }
            writeAttributes(attributes)
        }
    }

    fun certificateBag(certificate: ByteString, attributes: BagAttributes): ByteString {
        val value = Der.encode {
            sequence {
                objectIdentifier(Pkcs12Oids.X509_CERTIFICATE)
                explicit(0) { octetString(certificate) }
            }
        }
        return bag(type = Pkcs12Oids.CERTIFICATE_BAG, value = value, attributes = attributes)
    }

    fun safeContents(bags: List<ByteString>): ByteString = Der.encode { sequence { bags.forEach { bag -> raw(bag) } } }

    fun plain(contents: ByteString): ByteString = Der.encode {
        sequence {
            objectIdentifier(Pkcs12Oids.DATA)
            explicit(0) { octetString(contents) }
        }
    }

    fun encrypted(algorithm: ByteString, ciphertext: ByteString): ByteString = Der.encode {
        sequence {
            objectIdentifier(Pkcs12Oids.ENCRYPTED_DATA)
            explicit(0) {
                sequence {
                    integer(0L)
                    sequence {
                        objectIdentifier(Pkcs12Oids.DATA)
                        raw(algorithm)
                        element(Tag.context(number = 0, isConstructed = false), ciphertext)
                    }
                }
            }
        }
    }

    fun authenticatedSafe(contents: List<ByteString>): ByteString =
        Der.encode { sequence { contents.forEach { content -> raw(content) } } }

    fun pfx(authenticated: ByteString, salt: ByteString, iterations: Int, tag: ByteString): ByteString = Der.encode {
        sequence {
            integer(VERSION)
            raw(plain(authenticated))
            sequence {
                sequence {
                    writePbmac1(salt = salt, iterations = iterations)
                    octetString(tag)
                }
                octetString(salt)
                integer(iterations.toLong())
            }
        }
    }

    private fun DerWriter.writePbmac1(salt: ByteString, iterations: Int) {
        sequence {
            objectIdentifier(Pkcs12Oids.PBMAC1)
            sequence {
                sequence {
                    objectIdentifier(Pkcs12Oids.PBKDF2)
                    sequence {
                        octetString(salt)
                        integer(iterations.toLong())
                        integer(MAC_KEY_BYTES)
                        writeHmacSha256()
                    }
                }
                writeHmacSha256()
            }
        }
    }

    private fun DerWriter.writeHmacSha256() {
        sequence {
            objectIdentifier(Pkcs12Oids.HMAC_SHA256)
            nullValue()
        }
    }

    private fun DerWriter.writeAttributes(attributes: BagAttributes) {
        val isEmpty = attributes == BagAttributes()
        if (isEmpty) return
        setOf {
            attributes.friendlyName?.let { name -> attribute(Pkcs12Oids.FRIENDLY_NAME) { bmpString(name) } }
            attributes.localKeyId?.let { id -> attribute(Pkcs12Oids.LOCAL_KEY_ID) { octetString(id) } }
            if (attributes.isTrusted) {
                attribute(Pkcs12Oids.TRUSTED_KEY_USAGE) { objectIdentifier(Pkcs12Oids.ANY_EXTENDED_KEY_USAGE) }
            }
        }
    }

    private fun DerWriter.attribute(type: ObjectIdentifier, value: DerWriter.() -> Unit) {
        sequence {
            objectIdentifier(type)
            setOf(value)
        }
    }

    private fun DerWriter.bmpString(text: String) {
        val bytes = ByteArray(text.length * 2) { index ->
            (text[index / 2].code shr BYTE_BITS * (1 - index % 2)).toByte()
        }
        element(Tag.BmpString, ByteString(bytes))
    }
}
