const splittedUrl = require("splitted-url");
const { default: fetch } = require("node-fetch");

const INTERVAL = 20000;
const MAX_TRIES = 20;

const API_HTTP = `https://http-observatory.security.mozilla.org/api/v1`;

/**
 * Run a HTTP Mozilla scan for a given URL
 *
 * @param {string} url The full URL
 *
 * @returns {Promise<HttpScanResult>}
 */
const scan = (url, tries = MAX_TRIES) => {
  const hostname = splittedUrl(url).host;
  console.warn(`fetch mozilla HTTP API for ${url}`);
  return fetch(`${API_HTTP}/analyze?host=${hostname}&hidden=true&rescan=true`, {
    method: "POST",
  })
    .then((r) => r.json())
    .then((result) => {
      if (result.error) {
        console.error("e", result.error);
        throw new Error(result.error);
      }
      if (result.state === "FINISHED") {
        return fetch(`${API_HTTP}/getScanResults?scan=${result.scan_id}`, {
          method: "GET",
        })
          .then((r) => r.json())
          .then((details) => ({
            url,
            ...result,
            details,
          }));
      } else if (tries > 0) {
        console.warn(
          `delay HTTP ${url} (${MAX_TRIES - tries + 1}/${MAX_TRIES})`
        );
        return new Promise((resolve) =>
          setTimeout(() => scan(url, tries - 1).then(resolve), INTERVAL)
        );
      }
      throw new Error(`${MAX_TRIES} failed scans for ${url}`);
    });
};

module.exports = scan;
