/* ============================================================
   ThreatLens Scanner — background service worker
   · right-click context menus (page / link / selection)
   · color-coded toolbar badge with the last scanned score
   ============================================================ */
"use strict";

importScripts("shared.js");

/* ---------------- Context menus ---------------- */

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "tl-scan-page",
      title: "Scan this page with ThreatLens",
      contexts: ["page"],
    });
    chrome.contextMenus.create({
      id: "tl-scan-link",
      title: "Scan this link with ThreatLens",
      contexts: ["link"],
    });
    chrome.contextMenus.create({
      id: "tl-scan-selection",
      title: "Scan selected URL with ThreatLens",
      contexts: ["selection"],
    });
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const url = info.linkUrl || info.selectionText || (tab && tab.url);
  if (!url) return;
  chrome.tabs.create({ url: chrome.runtime.getURL(`results.html?url=${encodeURIComponent(url)}`) });
});

/* ---------------- Toolbar badge ---------------- */

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || !msg.type) return;
  if (msg.type === "set-badge") {
    chrome.action.setBadgeBackgroundColor({ color: TL.scoreColor(msg.score) });
    chrome.action.setBadgeText({ text: String(msg.score) });
    chrome.action.setTitle({ title: `ThreatLens: ${msg.score}/100 · ${msg.verdict || ""}` });
  } else if (msg.type === "clear-badge") {
    chrome.action.setBadgeText({ text: "" });
    chrome.action.setTitle({ title: "Scan with ThreatLens" });
  }
  sendResponse({ ok: true });
});
