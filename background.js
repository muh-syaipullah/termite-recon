/**
 * ============================================================
 *  Termite Recon - Chrome Extension
 *  Background Service Worker
 * ============================================================
 *  Copyright (c) 2025 muh-syaipullah
 *  GitHub  : https://github.com/muh-syaipullah
 *  License : MIT
 * ============================================================
 */

// Buka popup.html di tab baru jika user klik ikon extension (fallback)
chrome.action.onClicked.addListener(() => {
	chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') });
});
