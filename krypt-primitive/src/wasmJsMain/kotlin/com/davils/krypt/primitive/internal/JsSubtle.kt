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

@file:OptIn(ExperimentalWasmJsInterop::class)

package com.davils.krypt.primitive.internal

import kotlin.js.Promise

@JsFun("(name, data) => globalThis.crypto.subtle.digest(name, data)")
internal external fun digest(name: String, data: JsAny): Promise<JsAny>

@JsFun("(f, d, a, e, u) => globalThis.crypto.subtle.importKey(f, d, a, e, u)")
internal external fun importKey(f: String, d: JsAny, a: JsAny, e: Boolean, u: JsAny): Promise<JsAny>

@JsFun("(format, key) => globalThis.crypto.subtle.exportKey(format, key)")
internal external fun exportKey(format: String, key: JsAny): Promise<JsAny>

@JsFun("(algorithm, usages) => globalThis.crypto.subtle.generateKey(algorithm, true, usages)")
internal external fun generateKey(algorithm: JsAny, usages: JsAny): Promise<JsAny>

@JsFun("(algorithm, key, data) => globalThis.crypto.subtle.sign(algorithm, key, data)")
internal external fun sign(algorithm: JsAny, key: JsAny, data: JsAny): Promise<JsAny>

@JsFun("(algorithm, key, signature, data) => globalThis.crypto.subtle.verify(algorithm, key, signature, data)")
internal external fun verify(algorithm: JsAny, key: JsAny, signature: JsAny, data: JsAny): Promise<JsBoolean>

@JsFun("(algorithm, key, data) => globalThis.crypto.subtle.encrypt(algorithm, key, data)")
internal external fun encrypt(algorithm: JsAny, key: JsAny, data: JsAny): Promise<JsAny>

@JsFun("(algorithm, key, data) => globalThis.crypto.subtle.decrypt(algorithm, key, data)")
internal external fun decrypt(algorithm: JsAny, key: JsAny, data: JsAny): Promise<JsAny>

@JsFun("(algorithm, key, bits) => globalThis.crypto.subtle.deriveBits(algorithm, key, bits)")
internal external fun deriveBits(algorithm: JsAny, key: JsAny, bits: Int): Promise<JsAny>

@JsFun("(key, wrappingKey) => globalThis.crypto.subtle.wrapKey('raw', key, wrappingKey, 'AES-KW')")
internal external fun wrapKey(key: JsAny, wrappingKey: JsAny): Promise<JsAny>

@JsFun("(w, k, t) => globalThis.crypto.subtle.unwrapKey('raw', w, k, 'AES-KW', t, true, ['sign'])")
internal external fun unwrapKey(w: JsAny, k: JsAny, t: JsAny): Promise<JsAny>
