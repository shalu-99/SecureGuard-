"use strict";

const SECUREGUARD_API = "http://127.0.0.1:8000";

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    console.log("[SecureGuard] Message received:", message?.type);
    if (!message || message.type !== "SECUREGUARD_LOGIN_EVENT") {
        return;
    }

    const tabUrl = sender.tab?.url;

    if (!tabUrl) {
        sendResponse({ ok: false, error: "Website unavailable" });
        return;
    }

    let hostname;

    try {
        const parsedUrl = new URL(tabUrl);

        if (parsedUrl.protocol !== "https:") {
            sendResponse({ ok: false, error: "HTTPS websites only" });
            return;
        }

        hostname = parsedUrl.hostname;
    } catch {
        sendResponse({ ok: false, error: "Invalid website URL" });
        return;
    }

    chrome.storage.local.get(["secureguard_token"], async (result) => {
        const token = result.secureguard_token;

        if (!token) {
            sendResponse({
                ok: false,
                error: "Open the extension and save your SecureGuard token first"
            });
            return;
        }

        try {
            const response = await fetch(`${SECUREGUARD_API}/api/external-login`, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    website: hostname,
                    signal: message.signal,
                    details: message.signal === "possible_login_attempt"
                        ? "Login form submitted; successful login not confirmed"
                        : message.signal === "possible_post_login_navigation"
                            ? "Possible post-login navigation; success not confirmed"
                            : "Unverified browser event"
                })
            });

            if (!response.ok) {
                sendResponse({
                    ok: false,
                    error: `SecureGuard API returned HTTP ${response.status}`
                });
                return;
            }

            sendResponse({ ok: true, hostname });
        } catch {
            sendResponse({
                ok: false,
                error: "Could not connect to SecureGuard backend"
            });
        }
    });

    return true;
});
