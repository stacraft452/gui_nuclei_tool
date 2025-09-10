
const { app, BrowserWindow, ipcMain, shell, dialog } = require('electron');
const fs = require('fs');
// 文件选择对话框
ipcMain.handle('select-file', async (event, filter) => {
  const win = BrowserWindow.getFocusedWindow();
  const result = await dialog.showOpenDialog(win, {
    title: '选择 nuclei.exe 文件',
    properties: ['openFile'],
    filters: filter === 'exe' ? [{ name: 'EXE', extensions: ['exe'] }] : undefined
  });
  if (result.canceled || !result.filePaths.length) return '';
  return result.filePaths[0];
});

ipcMain.handle('select-folder', async (event) => {
  const win = BrowserWindow.getFocusedWindow();
  const result = await dialog.showOpenDialog(win, {
    title: '选择模板目录',
    properties: ['openDirectory']
  });
  if (result.canceled || !result.filePaths.length) return '';
  return result.filePaths[0];
});
const path = require('path');
const backend = require('../backend/backend.js');

function createWindow() {
  const win = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });
  win.loadFile(path.join(__dirname, '../../public/index.html'));
}

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// 配置存储与加载
const configPath = path.join(process.cwd(), 'config.json');
ipcMain.handle('get-config', () => {
  try {
    if (fs.existsSync(configPath)) {
      const raw = fs.readFileSync(configPath, 'utf-8');
      return JSON.parse(raw);
    }
    // 没有则返回空参数
    return { nucleiPath: '', templateDir: '', params: {}, templates: [], selectedTemplates: [] };
  } catch (e) {
    console.log('[config] get-config error:', e);
    return { nucleiPath: '', templateDir: '', params: {}, templates: [], selectedTemplates: [] };
  }
});
ipcMain.handle('set-config', (event, config) => {
  try {
    // 保证结构完整
    const safeConfig = {
      nucleiPath: config.nucleiPath || '',
      templateDir: config.templateDir || '',
      params: config.params || {},
      selectedTemplates: config.selectedTemplates || [],
      enableAI: config.enableAI !== false
    };
    fs.writeFileSync(configPath, JSON.stringify(safeConfig, null, 2));
    return true;
  } catch (e) {
    console.log('[config] set-config error:', e);
    return false;
  }
});

// 后端功能接口
// ...existing code...
ipcMain.handle('run-nuclei', async (event, params) => {
  // 每次扫描前保存配置到 config.json（覆盖）
  // 保留 enableAI 字段，优先用 params.enableAI，其次 config.json
  let enableAI = typeof params.enableAI !== 'undefined' ? params.enableAI : true;
  let safeConfig = {
    nucleiPath: params.nucleiPath || '',
    templateDir: params.templateDir || '',
    params: params.params || {},
    selectedTemplates: params.templates || [],
    enableAI: !!enableAI
  };
  try {
    if (fs.existsSync(configPath)) {
      try {
        const raw = fs.readFileSync(configPath, 'utf-8');
        const cfg = JSON.parse(raw);
        if (typeof cfg.enableAI !== 'undefined') safeConfig.enableAI = cfg.enableAI;
      } catch {}
    }
    fs.writeFileSync(configPath, JSON.stringify(safeConfig, null, 2));
  } catch (e) {
    console.log('[config] Failed to save config.json:', e);
  }
  // 进度推送：每次onProgress时通过event.sender.send('scan-progress', statusObj)
  // 传递 enableAI 参数，优先用 safeConfig
  return await backend.runNuclei({
    ...params,
    enableAI: !!safeConfig.enableAI,
    onProgress: (statusObj) => {
      event.sender.send('scan-progress', statusObj);
    }
  });
});

ipcMain.handle('abort-scan', async () => {
  return backend.abortNucleiScan();
});
ipcMain.handle('get-templates', async (event, templateDir) => {
  // 支持参数传递，优先用参数，否则用 config.json
  let dir = templateDir;
  if (!dir) {
    try {
      if (fs.existsSync(configPath)) {
        const raw = fs.readFileSync(configPath, 'utf-8');
        const config = JSON.parse(raw);
        dir = config.templateDir;
      }
    } catch {}
  }
  // 直接返回分组数组，确保可序列化
  const result = backend.getTemplates(dir);
  return JSON.parse(JSON.stringify(result));
});
ipcMain.handle('ai-explain', async (event, vuln) => {
  return await backend.aiExplain(vuln);
});
ipcMain.handle('export-result', async (event, data, type) => {
  const outPath = await backend.exportResult(data, type);
  // 自动打开文件夹
  if (outPath) {
    shell.showItemInFolder(outPath);
  }
  return outPath;
});
