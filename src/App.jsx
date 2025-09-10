import React, { useState, useEffect } from 'react';
// ...existing imports...

function App() {
  // ...existing state...
  const [config, setConfig] = useState({ nucleiPath: '', templateDir: '', params: {}, selectedTemplates: [], enableAI: true });
  // ...existing state...

  useEffect(() => {
    window.api.getConfig().then(cfg => {
      setConfig({ ...cfg, enableAI: cfg.enableAI !== false });
    });
  }, []);

  // ...existing handlers...
  const handleEnableAIChange = (e) => {
    const enableAI = e.target.checked;
    setConfig(cfg => ({ ...cfg, enableAI }));
    window.api.setConfig({ ...config, enableAI });
  };

  // ...existing UI...
  return (
    <div>
      {/* 参数输入区示例 */}
      <div style={{ margin: '16px 0', padding: '12px', background: '#f7f7fa', borderRadius: 8, boxShadow: '0 1px 4px #eee' }}>
        <div style={{ marginBottom: 8 }}>
          <label>nuclei路径：</label>
          <input style={{ width: 320 }} value={config.nucleiPath || ''} readOnly />
        </div>
        <div style={{ marginBottom: 8 }}>
          <label>模板目录：</label>
          <input style={{ width: 320 }} value={config.templateDir || ''} readOnly />
        </div>
        {/* 其它参数输入... */}
        <div style={{ margin: '12px 0' }}>
          <label style={{ fontWeight: 500 }}>
            <input type="checkbox" checked={!!config.enableAI} onChange={handleEnableAIChange} style={{ marginRight: 8 }} /> 启用AI解释
          </label>
        </div>
      </div>
      {/* ...existing UI... */}
    </div>
  );
}

export default App;
