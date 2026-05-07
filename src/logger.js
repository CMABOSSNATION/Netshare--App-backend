const colors = {
  reset:  '\x1b[0m',
  green:  '\x1b[32m',
  cyan:   '\x1b[36m',
  yellow: '\x1b[33m',
  red:    '\x1b[31m',
  gray:   '\x1b[90m',
};

function ts() {
  return new Date().toISOString().replace('T',' ').slice(0,19);
}

const logger = {
  info:  (msg) => console.log(`${colors.cyan}[${ts()}] INFO${colors.reset}  ${msg}`),
  ok:    (msg) => console.log(`${colors.green}[${ts()}] OK${colors.reset}    ${msg}`),
  warn:  (msg) => console.log(`${colors.yellow}[${ts()}] WARN${colors.reset}  ${msg}`),
  error: (msg) => console.log(`${colors.red}[${ts()}] ERROR${colors.reset} ${msg}`),
  debug: (msg) => console.log(`${colors.gray}[${ts()}] DEBUG${colors.reset} ${msg}`),
};

module.exports = logger;
