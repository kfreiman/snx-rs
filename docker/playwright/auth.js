const { chromium } = require("playwright");

const timeoutMs = Number(process.env.PLAYWRIGHT_TIMEOUT || 110) * 1000;
const callbackPort = process.env.PLAYWRIGHT_CALLBACK_PORT || "7779";
const debug = process.env.PLAYWRIGHT_DEBUG === "true";

function debugLog(message) {
  if (debug) {
    console.error(`Playwright: ${message}`);
  }
}

function pageSummary(page) {
  try {
    const url = new URL(page.url());
    return `${url.protocol}//${url.host}`;
  } catch {
    return `url=${page.url()}`;
  }
}

async function pageControls(page) {
  if (!debug) {
    return "";
  }

  try {
    const controls = await page.locator("button, a, input").evaluateAll((elements) => {
      const redact = (value) =>
        (value || "")
          .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "<email>")
          .slice(0, 80);

      return elements.slice(0, 20).map((element) => ({
        tag: element.tagName,
        type: element.getAttribute("type"),
        text: redact((element.innerText || "").trim()),
        aria: redact(element.getAttribute("aria-label")),
        placeholder: redact(element.getAttribute("placeholder")),
      }));
    });
    return JSON.stringify(controls);
  } catch {
    return "[]";
  }
}

async function pageState(page) {
  if (!debug) {
    return "";
  }

  try {
    const text = await page.locator("body").innerText().catch(() => "");
    return JSON.stringify({
      frames: page.frames().map((frame) => pageSummary({ url: () => frame.url() })),
      title: await page.title().catch(() => ""),
      htmlLength: (await page.content()).length,
      textLength: text.length,
    });
  } catch {
    return "{}";
  }
}

async function fillAcrossFrames(page, selector, value) {
  for (const frame of page.frames()) {
    if (await fillIfVisible(frame, selector, value)) {
      return true;
    }
  }
  return false;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isCallbackUrl(value) {
  try {
    const url = new URL(value);
    const isLocal = url.hostname === "127.0.0.1" || url.hostname === "localhost";
    return isLocal && url.port === callbackPort && url.pathname.length > 1;
  } catch {
    return false;
  }
}

async function readChallengeUrl() {
  let input = "";
  for await (const chunk of process.stdin) {
    input += chunk;
  }

  const url = input.trim().split(/\r?\n/, 1)[0];
  if (!url || !/^https?:\/\//.test(url)) {
    throw new Error("invalid challenge URL");
  }
  return url;
}

async function fillIfVisible(page, selector, value) {
  if (!value) {
    return false;
  }

  const field = page.locator(selector).first();
  try {
    await field.waitFor({ state: "visible", timeout: 1_000 });
    await field.fill(value);
    await field.press("Enter");
    await page.waitForTimeout(500);
    debugLog(`filled ${selector.split(",")[0]}`);
    return true;
  } catch {
    debugLog(`field not found ${selector.split(",")[0]}`);
    return false;
  }
}

async function fillAcrossPages(context, selector, value) {
  if (!value) {
    return false;
  }

  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    for (const page of context.pages()) {
      if (await fillAcrossFrames(page, selector, value)) {
        return true;
      }
    }
    await sleep(250);
  }
  return false;
}

async function clickAcrossPages(context, selector) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    for (const page of context.pages()) {
      for (const frame of page.frames()) {
        const button = frame.locator(selector).first();
        try {
          await button.waitFor({ state: "visible", timeout: 1_000 });
          await button.click();
          await page.waitForTimeout(500);
          return true;
        } catch {
          continue;
        }
      }
    }
    await sleep(250);
  }
  return false;
}

async function completeConfiguredLogin(context) {
  await fillAcrossPages(context, 'input[type="email"], input[name="identifier"]', process.env.PLAYWRIGHT_USERNAME);
  await fillAcrossPages(context, 'input[type="password"]', process.env.PLAYWRIGHT_PASSWORD);
  await fillAcrossPages(
    context,
    'input[name="totp"], input[autocomplete="one-time-code"], input[aria-label*="code" i]',
    process.env.PLAYWRIGHT_OTP,
  );

  if (!process.env.PLAYWRIGHT_OTP && (await clickAcrossPages(context, 'button:has-text("Resend it")'))) {
    debugLog("resent Google Prompt");
  }
}

async function waitForCallback(context) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    for (const page of context.pages()) {
      if (isCallbackUrl(page.url())) {
        return;
      }
    }
    await sleep(250);
  }

  debugLog(
    `callback timeout; pages=${context.pages().map((page) => pageSummary(page)).join(" | ")}`,
  );
  throw new Error("authentication callback was not received");
}

async function main() {
  const challengeUrl = await readChallengeUrl();
  const context = await chromium.launchPersistentContext("/tmp/playwright-profile", {
    headless: true,
    args: ["--no-sandbox"],
  });

  try {
    const page = context.pages()[0] || (await context.newPage());
    await page.goto(challengeUrl, { waitUntil: "domcontentloaded", timeout: timeoutMs }).catch((error) => {
      debugLog(`initial navigation failed: ${error.name}`);
    });
    debugLog(`initial page ${pageSummary(page)} state=${await pageState(page)} controls=${await pageControls(page)}`);

    if (!isCallbackUrl(page.url())) {
      await completeConfiguredLogin(context);
      for (const currentPage of context.pages()) {
        debugLog(
          `after configured login ${pageSummary(currentPage)} state=${await pageState(currentPage)} controls=${await pageControls(currentPage)}`,
        );
      }
    }

    await waitForCallback(context);
  } finally {
    await context.close();
  }
}

main().catch((error) => {
  let message = error instanceof Error ? error.message : "unknown error";
  for (const secret of [process.env.PLAYWRIGHT_USERNAME, process.env.PLAYWRIGHT_PASSWORD, process.env.PLAYWRIGHT_OTP]) {
    if (secret) {
      message = message.split(secret).join("<redacted>");
    }
  }
  message = message.replace(/https?:\/\/\S+/g, "<url>").slice(0, 500);
  console.error(`Playwright authentication failed: ${message}`);
  process.exit(1);
});
