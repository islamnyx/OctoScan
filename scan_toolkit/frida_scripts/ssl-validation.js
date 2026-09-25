/*
 * ssl-validation.js — observe TLS validation behaviour at runtime.
 *
 * Hooks:
 *   X509TrustManager.checkServerTrusted — records the implementing class.
 *     (An empty implementation = trust-all = the finding; the class name
 *     is the evidence. We do NOT weaken validation, only observe.)
 *   HostnameVerifier.verify — records calls returning true.
 *   SslErrorHandler.proceed (WebView) — records proceed() calls, i.e. the
 *     app tapping through certificate errors.
 *   HttpURLConnection / OkHttp plain-http URLs — cleartext observations.
 *
 * Output: one JSON object per line via send().
 * Run: frida -U -l ssl-validation.js --no-pause -f <package>
 */
(function () {
    'use strict';

    function emit(event, data) {
        send(JSON.stringify(Object.assign({ script: 'ssl-validation', event: event }, data)));
    }

    Java.perform(function () {
        // ---- TrustManager implementations ----
        try {
            var X509TM = Java.use('javax.net.ssl.X509TrustManager');
            X509TM.checkServerTrusted.implementation = function (chain, authType) {
                emit('trustmanager-check', {
                    impl: this.$className,
                    chain_len: chain ? chain.length : 0,
                    auth_type: String(authType)
                });
                return this.checkServerTrusted(chain, authType);
            };
        } catch (e) { emit('hook-error', { hook: 'X509TrustManager', error: String(e) }); }

        // ---- HostnameVerifier ----
        try {
            var HV = Java.use('javax.net.ssl.HostnameVerifier');
            HV.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation =
                function (hostname, session) {
                    var result = this.verify(hostname, session);
                    emit('hostname-verify', {
                        impl: this.$className,
                        hostname: String(hostname),
                        result: Boolean(result)
                    });
                    return result;
                };
        } catch (e) { emit('hook-error', { hook: 'HostnameVerifier', error: String(e) }); }

        // ---- WebView SSL error proceed ----
        try {
            var SslHandler = Java.use('android.webkit.SslErrorHandler');
            SslHandler.proceed.implementation = function () {
                emit('webview-ssl-proceed', {});
                return this.proceed();
            };
        } catch (e) { emit('hook-error', { hook: 'SslErrorHandler', error: String(e) }); }

        // ---- Cleartext URLs ----
        try {
            var URL = Java.use('java.net.URL');
            URL.$init.overload('java.lang.String').implementation = function (spec) {
                if (String(spec).toLowerCase().indexOf('http://') === 0) {
                    var host = String(spec).slice(7).split('/')[0];
                    if (host !== '127.0.0.1' && host !== 'localhost' && host !== '10.0.2.2') {
                        emit('cleartext-url', { url: String(spec).slice(0, 200) });
                    }
                }
                return this.$init(spec);
            };
        } catch (e) { emit('hook-error', { hook: 'java.net.URL', error: String(e) }); }
    });
})();
