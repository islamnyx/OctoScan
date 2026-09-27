/*
 * insecure-storage.js — observe plaintext writes to app-local storage.
 *
 * Hooks:
 *   SharedPreferences.Editor.putString / putStringSet / commit / apply
 *   Context.openFileOutput (flags — MODE_WORLD_READABLE == 1 is the finding)
 *   SQLiteDatabase.execSQL / insert (table + statement shape, not row data)
 *
 * Output: one JSON object per line via send(). Values are truncated to
 * 64 chars — storage keys/paths are the evidence, not the user's data.
 * Run: frida -U -l insecure-storage.js --no-pause -f <package>
 */
(function () {
    'use strict';

    function emit(event, data) {
        send(JSON.stringify(Object.assign({ script: 'insecure-storage', event: event }, data)));
    }

    function clip(s) {
        if (s === null || s === undefined) { return null; }
        s = String(s);
        return s.length > 64 ? s.slice(0, 64) + '…' : s;
    }

    Java.perform(function () {
        // ---- SharedPreferences writes ----
        try {
            var Editor = Java.use('android.content.SharedPreferences$Editor');
            Editor.putString.implementation = function (key, value) {
                emit('shared-prefs-write', { key: String(key), value: clip(value) });
                return this.putString(key, value);
            };
            Editor.putStringSet.implementation = function (key, values) {
                emit('shared-prefs-write-set', { key: String(key) });
                return this.putStringSet(key, values);
            };
        } catch (e) { emit('hook-error', { hook: 'SharedPreferences.Editor', error: String(e) }); }

        // ---- openFileOutput mode ----
        try {
            var ContextWrapper = Java.use('android.content.ContextWrapper');
            ContextWrapper.openFileOutput.implementation = function (name, mode) {
                if (mode === 1 || mode === 2) {  // WORLD_READABLE / WORLD_WRITEABLE
                    emit('world-accessible-file', { name: String(name), mode: mode });
                } else {
                    emit('file-write', { name: String(name), mode: mode });
                }
                return this.openFileOutput(name, mode);
            };
        } catch (e) { emit('hook-error', { hook: 'openFileOutput', error: String(e) }); }

        // ---- SQLite ----
        try {
            var SQLiteDB = Java.use('android.database.sqlite.SQLiteDatabase');
            SQLiteDB.execSQL.overload('java.lang.String').implementation = function (sql) {
                emit('sqlite-exec', { sql: clip(sql) });
                return this.execSQL(sql);
            };
        } catch (e) { emit('hook-error', { hook: 'SQLiteDatabase', error: String(e) }); }
    });
})();
