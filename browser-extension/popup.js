"use strict";

const tokenInput = document.getElementById("token");
const saveButton = document.getElementById("save");
const status = document.getElementById("status");

chrome.storage.local.get(["secureguard_token"], (result) => {
    if (result.secureguard_token) {
        tokenInput.value = result.secureguard_token;
        status.textContent = "Saved token is available.";
    }
});

saveButton.addEventListener("click", () => {
    const token = tokenInput.value.trim();

    if (!token) {
        status.textContent = "Enter a SecureGuard access token.";
        return;
    }

    chrome.storage.local.set({ secureguard_token: token }, () => {
        status.textContent = chrome.runtime.lastError
            ? "Could not save token."
            : "Token saved locally.";
    });
});


const testButton = document.getElementById("test");

testButton.addEventListener("click", async () => {
    status.textContent = "Sending test event...";
    testButton.disabled = true;

    try {
        const result = await chrome.storage.local.get(["secureguard_token"]);
        const token = result.secureguard_token;

        if (!token) {
            status.textContent = "Save your SecureGuard token first.";
            return;
        }

        const response = await fetch("http://127.0.0.1:8000/api/external-login", {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                website: "extension-test.example",
                signal: "possible_post_login_navigation",
                details: "SecureGuard extension test event; not a real login"
            })
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            status.textContent = `Test failed: HTTP ${response.status} ${data.detail || ""}`;
            return;
        }

        status.textContent = "Test event sent successfully. Check your dashboard.";
    } catch (error) {
        status.textContent = "Could not connect. Check that the backend is running.";
    } finally {
        testButton.disabled = false;
    }
});
