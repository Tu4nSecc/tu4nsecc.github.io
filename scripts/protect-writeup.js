const fs = require("fs");
const crypto = require("crypto");

const [htmlPath, dataPath, contentPath, password] = process.argv.slice(2);
if (!htmlPath || !dataPath || !contentPath || !password) {
  throw new Error("Usage: node protect-writeup.js <html> <data.json> <content.md> <password>");
}

const html = fs.readFileSync(htmlPath, "utf8");
const startTag = '<div class="e-content article-entry" itemprop="articleBody">';
const start = html.indexOf(startTag);
const footer = html.indexOf('<footer class="article-footer">', start);
if (start < 0 || footer < 0) throw new Error("Could not locate the rendered article body");

const body = html.slice(start + startTag.length, footer).replace(/<\/div>\s*$/, "").trim();
const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const key = crypto.pbkdf2Sync(password, salt, 250000, 32, "sha256");
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ciphertext = Buffer.concat([cipher.update(body, "utf8"), cipher.final()]);
const tag = cipher.getAuthTag();

const payload = {
  algorithm: "AES-GCM",
  kdf: "PBKDF2-SHA-256",
  iterations: 250000,
  salt: salt.toString("base64"),
  iv: iv.toString("base64"),
  ciphertext: ciphertext.toString("base64"),
  tag: tag.toString("base64"),
};

fs.mkdirSync(require("path").dirname(dataPath), { recursive: true });
fs.writeFileSync(dataPath, JSON.stringify(payload, null, 2) + "\n");
fs.writeFileSync(
  contentPath,
  `---\ntitle: "Holmes CTF 2026"\ndate: 2026-09-17T14:20:00+07:00\ndraft: false\nprotected: true\ndescription: "A password-protected digital forensics writeup for the Paper Ghost challenge."\ncategories: ["CTF", "writeup", "forensics"]\ncover: "/images/holmes_2026/paper_ghost/anh1.png"\n---\n`,
);

console.log(`Encrypted ${body.length} rendered characters into ${dataPath}`);
