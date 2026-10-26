(() => {
    "use strict";

    if (window.location.protocol !== "https:") return;

    const hostname = window.location.hostname;
    const authPath = /login|signin|sign-in|authenticate|auth\/|oauth|checkpoint/i;

    if (!authPath.test(window.location.pathname)) {
        console.log("[SecureGuard] Page is not a recognized login page");
        return;
    }

    function reportLoginAttempt() {
        chrome.runtime.sendMessage({
            type: "SECUREGUARD_LOGIN_EVENT",
            signal: "possible_login_attempt"
        }, (response) => {
            if (chrome.runtime.lastError) {
                console.warn("[SecureGuard] Could not send event");
                return;
            }

            console.info(
                "[SecureGuard] Login attempt:",
                hostname,
                response?.ok ? "reported" : "not reported"
            );
        });
    }

    document.addEventListener("submit", (event) => {
        const form = event.target;
        if (!(form instanceof HTMLFormElement)) return;

        const passwordField = form.querySelector('input[type="password"]');
        if (passwordField) {
            reportLoginAttempt();
        }
    }, true);

    console.log("[SecureGuard] Login form detection ready:", hostname);
})();
