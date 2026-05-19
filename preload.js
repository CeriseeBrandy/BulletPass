const { contextBridge } = require("electron");
const fs = require("fs");
const path = require("path");

const BACKUP_DIR = path.join(__dirname, "backups");
const MAX_BACKUPS = 20;

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function rotateBackups(dir) {
  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith(".bullet"))
    .map(f => ({
      name: f,
      path: path.join(dir, f),
      time: fs.statSync(path.join(dir, f)).mtimeMs
    }))
    .sort((a, b) => b.time - a.time);

  files.slice(MAX_BACKUPS).forEach(file => {
    fs.unlinkSync(file.path);
  });
}

contextBridge.exposeInMainWorld("bulletBackup", {
  saveBackup(type, content) {
    const dir = path.join(BACKUP_DIR, type);
    ensureDir(dir);

    const filename = `backup-${Date.now()}.bullet`;
    const filepath = path.join(dir, filename);

    fs.writeFileSync(filepath, content, "utf8");
    rotateBackups(dir);

    return filepath;
  }
});