/*
 * weak-crypto.js — observe use of broken/legacy crypto primitives.
 *
 * Hooks:
 *   MessageDigest.getInstance  (flags MD5 / SHA-1 for security use)
 *   Cipher.getInstance         (flags DES / DESede / ECB modes)
 *   SecureRandom.setSeed(byte[]) with a static-looking seed is noted by
 *   the analyst — the hook only records that setSeed(byte[]) was called.
 *
 * Output: one JSON object per line via send().
 * Run: frida -U -l weak-crypto.js --no-pause -f <package>
 */
(function () {
    'use strict';

    function emit(event, data) {
        send(JSON.stringify(Object.assign({ script: 'weak-crypto', event: event }, data)));
    }

    Java.perform(function () {
        try {
            var MessageDigest = Java.use('java.security.MessageDigest');
            MessageDigest.getInstance.overload('java.lang.String').implementation = function (algo) {
                var a = String(algo).toUpperCase().replace(/-/g, '');
                if (a === 'MD5' || a === 'SHA1' || a === 'SHA') {
                    emit('weak-hash', { algorithm: String(algo) });
                } else {
                    emit('hash-use', { algorithm: String(algo) });
                }
                return this.getInstance(algo);
            };
        } catch (e) { emit('hook-error', { hook: 'MessageDigest', error: String(e) }); }

        try {
            var Cipher = Java.use('javax.crypto.Cipher');
            Cipher.getInstance.overload('java.lang.String').implementation = function (trans) {
                var t = String(trans).toUpperCase();
                if (t.indexOf('DES') !== -1 || t.indexOf('ECB') !== -1) {
                    emit('weak-cipher', { transformation: String(trans) });
                } else {
                    emit('cipher-use', { transformation: String(trans) });
                }
                return this.getInstance(trans);
            };
        } catch (e) { emit('hook-error', { hook: 'Cipher', error: String(e) }); }

        try {
            var SecureRandom = Java.use('java.security.SecureRandom');
            SecureRandom.setSeed.overload('[B').implementation = function (seed) {
                emit('securerandom-seed', { seed_len: seed.length });
                return this.setSeed(seed);
            };
        } catch (e) { emit('hook-error', { hook: 'SecureRandom', error: String(e) }); }
    });
})();
