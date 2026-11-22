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

@JsFun("(size) => new Uint8Array(size)")
internal external fun newBytes(size: Int): JsAny

@JsFun("(b, at, v, n) => { for (let i = 0; i < n; i++) { b[at + i] = (v >>> (8 * i)) & 255; } }")
internal external fun putInt(b: JsAny, at: Int, v: Int, n: Int)

@JsFun("(b, i) => b[i] | ((b[i + 1] || 0) << 8) | ((b[i + 2] || 0) << 16) | ((b[i + 3] || 0) << 24)")
internal external fun intAt(b: JsAny, i: Int): Int

@JsFun("(buffer) => buffer.byteLength")
internal external fun byteLength(buffer: JsAny): Int

@JsFun("(buffer) => new Uint8Array(buffer)")
internal external fun viewOf(buffer: JsAny): JsAny

@JsFun("(bytes) => { if (bytes instanceof Uint8Array) bytes.fill(0); }")
internal external fun wipe(bytes: JsAny)

@JsFun("(reason) => String(reason && reason.name ? reason.name : reason)")
internal external fun describe(reason: JsAny?): String

@JsFun("(list) => list.length === 0 ? [] : list.split(',')")
internal external fun usages(list: String): JsAny

@JsFun("(pair) => pair.publicKey")
internal external fun publicOf(pair: JsAny): JsAny

@JsFun("(pair) => pair.privateKey")
internal external fun privateOf(pair: JsAny): JsAny
