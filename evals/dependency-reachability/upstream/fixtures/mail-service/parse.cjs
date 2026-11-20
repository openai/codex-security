const { simpleParser } = require('../index.js');
const config = require('./deploy.json');
const envelope = Buffer.from([
  'From: sender@example.invalid',
  'To: archive@example.invalid',
  'Content-Type: text/plain; charset=utf-8',
  '',
  '',
].join('\r\n'));

function replaceHeaders(raw) {
  let start = 0;
  while (start < raw.length) {
    const lf = raw.indexOf(0x0a, start);
    if (lf < 0) break;
    if (lf === start || (lf === start + 1 && raw[start] === 0x0d)) {
      return Buffer.concat([envelope, raw.subarray(lf + 1)]);
    }
    start = lf + 1;
  }
  throw new Error('Missing end of message headers');
}

module.exports = (raw) => {
  const options = { skipTextLinks: config.skipTextLinks };
  if (config.nativeCharset) options.Iconv = require('iconv').Iconv;
  return simpleParser(config.stripHeaders ? replaceHeaders(raw) : raw, options);
};
