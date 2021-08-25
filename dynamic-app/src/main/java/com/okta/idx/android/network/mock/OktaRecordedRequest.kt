/*
 * Copyright 2021-Present Okta, Inc.
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
package com.okta.idx.android.network.mock

import okhttp3.mockwebserver.RecordedRequest
import java.util.concurrent.atomic.AtomicReference

class OktaRecordedRequest(private val recordedRequest: RecordedRequest) {
    private val _bodyText = AtomicReference<String?>()

    val method: String? = recordedRequest.method
    val path: String? = recordedRequest.path

    val bodyText: String
        get() {
            if (_bodyText.get() == null) {
                synchronized(_bodyText) {
                    if (_bodyText.get() == null) {
                        val actual = recordedRequest.body.readUtf8()
                        _bodyText.set(actual)
                    }
                }
            }
            return _bodyText.get()!!
        }
}
