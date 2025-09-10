const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  getConfig: () => ipcRenderer.invoke('get-config'),
  setConfig: (config) => ipcRenderer.invoke('set-config', config),
  runNuclei: (params) => ipcRenderer.invoke('run-nuclei', params),
  getTemplates: (templateDir) => ipcRenderer.invoke('get-templates', templateDir),
  aiExplain: (vuln) => ipcRenderer.invoke('ai-explain', vuln),
  exportResult: (data, type) => ipcRenderer.invoke('export-result', data, type),
  onScanProgress: (callback) => {
    ipcRenderer.removeAllListeners('scan-progress');
    ipcRenderer.on('scan-progress', (event, statusObj) => {
      callback(statusObj);
    });
  },
  selectFile: (filter) => ipcRenderer.invoke('select-file', filter),
  selectFolder: () => ipcRenderer.invoke('select-folder'),
  abortScan: () => ipcRenderer.invoke('abort-scan')
});
