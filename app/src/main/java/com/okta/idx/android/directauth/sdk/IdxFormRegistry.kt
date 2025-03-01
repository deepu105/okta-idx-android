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
package com.okta.idx.android.directauth.sdk

import com.okta.idx.android.directauth.sdk.forms.ForgotPasswordForm
import com.okta.idx.android.directauth.sdk.forms.RegisterForm
import com.okta.idx.android.directauth.sdk.forms.RegisterPasswordForm
import com.okta.idx.android.directauth.sdk.forms.RegisterPhoneForm
import com.okta.idx.android.directauth.sdk.forms.SelectAuthenticatorForm
import com.okta.idx.android.directauth.sdk.forms.SelectFactorForm
import com.okta.idx.android.directauth.sdk.forms.LaunchForm
import com.okta.idx.android.directauth.sdk.forms.UsernamePasswordForm
import com.okta.idx.android.directauth.sdk.forms.VerifyCodeForm
import com.okta.idx.android.directauth.sdk.viewFactories.ForgotPasswordFormViewFactory
import com.okta.idx.android.directauth.sdk.viewFactories.RegisterFormViewFactory
import com.okta.idx.android.directauth.sdk.viewFactories.RegisterPasswordFormViewFactory
import com.okta.idx.android.directauth.sdk.viewFactories.RegisterPhoneFormViewFactory
import com.okta.idx.android.directauth.sdk.viewFactories.SelectAuthenticatorFormViewFactory
import com.okta.idx.android.directauth.sdk.viewFactories.SelectFactorFormViewFactory
import com.okta.idx.android.directauth.sdk.viewFactories.LaunchFormViewFactory
import com.okta.idx.android.directauth.sdk.viewFactories.UsernamePasswordFormViewFactory
import com.okta.idx.android.directauth.sdk.viewFactories.VerifyCodeFormViewFactory

object IdxFormRegistry {
    private val viewFactories = mutableMapOf<Class<out Form>, FormViewFactory<*>>()

    init {
        register(UsernamePasswordForm::class.java, UsernamePasswordFormViewFactory())
        register(RegisterForm::class.java, RegisterFormViewFactory())
        register(RegisterPasswordForm::class.java, RegisterPasswordFormViewFactory())
        register(RegisterPhoneForm::class.java, RegisterPhoneFormViewFactory())
        register(ForgotPasswordForm::class.java, ForgotPasswordFormViewFactory())
        register(SelectAuthenticatorForm::class.java, SelectAuthenticatorFormViewFactory())
        register(SelectFactorForm::class.java, SelectFactorFormViewFactory())
        register(VerifyCodeForm::class.java, VerifyCodeFormViewFactory())
        register(LaunchForm::class.java, LaunchFormViewFactory())
    }

    fun <F : Form> register(
        clazz: Class<F>,
        formViewFactory: FormViewFactory<F>
    ) {
        viewFactories[clazz] = formViewFactory
    }

    fun <F : Form> getDisplayableForm(form: F): DisplayableForm<F> {
        @Suppress("UNCHECKED_CAST")
        return DisplayableForm(viewFactories[form.javaClass]!! as FormViewFactory<F>, form)
    }
}
