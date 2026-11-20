const { simpleParser } = require("../index.js");

async function indexMail(input) {
  const mail = await simpleParser(input);
  process.stdout.write(JSON.stringify({ subject: mail.subject, to: mail.to?.text }) + "\n");
}

indexMail(process.stdin).catch(error => {
  console.error(error);
  process.exitCode = 1;
});
