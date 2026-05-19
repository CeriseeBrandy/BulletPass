const { app, BrowserWindow, shell } = require("electron");
const path = require("path");
const fs = require("fs");

function createWindow() {
 const win = new BrowserWindow({
  width: 1200,
  height: 800,
  minWidth: 1000,
  minHeight: 700,
  autoHideMenuBar: true,
  title: "Bullet",
  icon: path.join(__dirname, "assets", "icon.png"),
  webPreferences: {
    contextIsolation: true,
    nodeIntegration: false,
    sandbox: false,
    webSecurity: true,
    devTools: false,
    preload: path.join(__dirname, "preload.js")
  }
});

  win.loadFile(path.join(__dirname, "login.html"));

  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("file://")) {
      return { action: "allow" };
    }

    shell.openExternal(url);
    return { action: "deny" };
  });

  win.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith("file://")) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  win.webContents.on("devtools-opened", () => {
    win.webContents.closeDevTools();
  });

  win.webContents.on("before-input-event", (event, input) => {
    const key = input.key.toLowerCase();

    if (
      key === "f12" ||
      (input.control && input.shift && ["i", "j", "c"].includes(key))
    ) {
      event.preventDefault();
    }
  });

  win.webContents.on("context-menu", event => {
    event.preventDefault();
  });
}

app.whenReady().then(() => {
  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});