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
package com.okta.idx.kotlin.infrastructure.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.tls.HandshakeCertificates
import org.junit.rules.TestRule
import org.junit.runner.Description
import org.junit.runners.model.Statement
import java.net.Proxy

class NetworkRule : TestRule {
    override fun apply(base: Statement, description: Description): Statement {
        return MockWebServerStatement(base, OktaMockWebServer.dispatcher, description)
    }

    fun enqueue(vararg requestMatcher: RequestMatcher, responseFactory: (MockResponse) -> Unit) {
        OktaMockWebServer.dispatcher.enqueue(*requestMatcher) { response ->
            responseFactory(response)
        }
    }

    fun mockedUrl(): String {
        return OktaMockWebServer.mockWebServer.url("").toString()
    }

    fun okHttpClient(): OkHttpClient {
        val clientBuilder = OkHttpClient.Builder()
        // This prevents Charles proxy from messing our mock responses.
        clientBuilder.proxy(Proxy.NO_PROXY)

        val handshakeCertificates = HandshakeCertificates.Builder()
            .addTrustedCertificate(OktaMockWebServer.localhostCertificate.certificate)
            .build()
        clientBuilder.sslSocketFactory(
            handshakeCertificates.sslSocketFactory(),
            handshakeCertificates.trustManager
        )

        clientBuilder.addInterceptor(OktaMockWebServer.interceptor)

        return clientBuilder.build()
    }
}
