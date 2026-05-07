const httpProxy = require('http-proxy');
const logger = require('./logger');

// HTTP proxy instance — forwards client HTTP requests
// through the relay to the host's internet connection
const proxy = httpProxy.createProxyServer({
  changeOrigin: true,
  secure: false,
  timeout: 15000,
  proxyTimeout: 15000,
});

proxy.on('error', (err, req, res) => {
  logger.error(`Proxy error: ${err.message}`);
  if (res && res.writeHead) {
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Proxy tunnel error', detail: err.message }));
  }
});

proxy.on('proxyReq', (proxyReq, req) => {
  logger.debug(`Proxying: ${req.method} ${req.url}`);
});

proxy.on('proxyRes', (proxyRes, req) => {
  logger.debug(`Response: ${proxyRes.statusCode} ← ${req.url}`);
});

// Forward an HTTP request through the proxy
function forwardRequest(req, res, targetUrl) {
  try {
    proxy.web(req, res, { target: targetUrl });
  } catch (err) {
    logger.error(`Forward failed: ${err.message}`);
    res.status(500).json({ error: 'Proxy forward failed' });
  }
}

module.exports = { proxy, forwardRequest };
