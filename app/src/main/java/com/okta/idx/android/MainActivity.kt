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
package com.okta.idx.android

import android.content.Intent
import android.os.Bundle
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import com.okta.idx.android.directauth.sdk.SocialRedirect

class MainActivity : AppCompatActivity() {
    companion object {
        const val SOCIAL_REDIRECT_ACTION = "SocialRedirect"
    }

    private val viewModel by viewModels<MainActivityViewModel>()

    private var gotSocialRedirect: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.activity_main)
    }

    override fun onResume() {
        super.onResume()

        if (!gotSocialRedirect) {
            viewModel.socialRedirectListener?.invoke(SocialRedirect.Cancelled)
        }
        gotSocialRedirect = false
    }

    public override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)

        if (intent?.action == SOCIAL_REDIRECT_ACTION) {
            intent.data?.let {
                gotSocialRedirect = true
                viewModel.socialRedirectListener?.invoke(SocialRedirect.Data(it))
            }
        }
    }
}
