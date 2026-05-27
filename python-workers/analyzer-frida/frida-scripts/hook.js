Java.perform(function () {
    console.log("[*] GenTriage Frida Sandbox Initialized");

    // 1. Hooking Network Calls (java.net.URL)
    try {
        var URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function (url) {
            var payload = {
                "type": "network",
                "action": "URL_INIT",
                "data": url
            };
            send(JSON.stringify(payload));
            return this.$init(url);
        };
        console.log("[+] Successfully hooked java.net.URL");
    } catch (e) {
        console.log("[-] Failed to hook java.net.URL: " + e.message);
    }

    // 2. Hooking Cryptographic Operations (javax.crypto.Cipher)
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.doFinal.overload('[B').implementation = function (data) {
            var payload = {
                "type": "crypto",
                "action": "CIPHER_DO_FINAL",
                "data": "Captured byte array of length: " + data.length
            };
            send(JSON.stringify(payload));
            return this.doFinal(data);
        };
        console.log("[+] Successfully hooked javax.crypto.Cipher");
    } catch (e) {
        console.log("[-] Failed to hook javax.crypto.Cipher: " + e.message);
    }

    // 3. Hooking Base64 Encoding (android.util.Base64)
    try {
        var Base64 = Java.use('android.util.Base64');
        Base64.encodeToString.overload('[B', 'int').implementation = function (data, flags) {
            var result = this.encodeToString(data, flags);
            var payload = {
                "type": "encoding",
                "action": "BASE64_ENCODE",
                "data": result
            };
            send(JSON.stringify(payload));
            return result;
        };
        console.log("[+] Successfully hooked android.util.Base64");
    } catch (e) {
        console.log("[-] Failed to hook android.util.Base64: " + e.message);
    }
});