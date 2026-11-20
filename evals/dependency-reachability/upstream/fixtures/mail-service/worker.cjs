const parse = require('./parse.cjs');

process.on('message', async (raw) => {
  const mail = await parse(raw);
  console.log(JSON.stringify({ messageId: mail.messageId, subject: mail.subject }));
});
