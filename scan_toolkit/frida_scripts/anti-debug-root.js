/*
 * anti-debug-root.js — observe debugger attachment and root-evasion signals.
 *
 * Hooks (OBSERVE ONLY — this script does not bypass anything):
 *   Debug.isDebuggerConnected — records polls and positive hits.
 *   Runtime.exec — records argv (flags su / mount / getprop invocations,
 *     i.e. the app performing its own root checks — useful context for
 *     the root-detection-bypass test).
 *   SystemProperties.get / __system_property_get for ro.debuggable,
 *     ro.secure — records reads of the emulator/debug flags.
 *
 * A "root-detection bypass" test itself is an analyst action (patch the
 * check with Frida and re-run); this script provides the observation
 * baseline that tells the analyst WHICH check to bypass.
 *
 * Output: one JSON object per line via send().
 * Run: frida -U -l anti-debug-root.js --no-pause -f <package>
 */
(function () {
    'use strict';

    function emit(event, data) {
        send(JSON.stringify(Object.assign({ script: 'anti-debug-root', event: event }, data)));
    }

    Java.perform(function () {
        // ---- Debugger attachment ----
        try {
            var Debug = Java.use('android.os.Debug');
            Debug.isDebuggerConnected.implementation = function () {
                var result = this.isDebuggerConnected();
                if (result) { emit('debugger-connected', {}); }
                return result;
            };
        } catch (e) { emit('hook-error', { hook: 'Debug', error: String(e) }); }

        // ---- Runtime.exec (su / root-check commands) ----
        try {
            var Runtime = Java.use('java.lang.Runtime');
            Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmdarray) {
                var cmds = [];
                for (var i = 0; i < cmdarray.length; i++) { cmds.push(String(cmdarray[i])); }
                var joined = cmds.join(' ');
                if (/(^|\s|\/)(su|busybox|magisk|mount|getprop|which)(\s|$)/.test(joined)) {
                    emit('sensitive-exec', { argv: cmds.slice(0, 8) });
                }
                return this.exec(cmdarray);
            };
        } catch (e) { emit('hook-error', { hook: 'Runtime.exec', error: String(e) }); }

        // ---- Build tags / debuggable reads ----
        try {
            var Build = Java.use('android.os.Build');
            var tags = String(Build.TAGS.value);
            emit('build-tags', { tags: tags });
        } catch (e) { emit('hook-error', { hook: 'Build.TAGS', error: String(e) }); }
    });
})();
