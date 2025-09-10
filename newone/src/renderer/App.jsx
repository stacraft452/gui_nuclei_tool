import React, { useEffect, useState } from 'react';

import { Box, Card, CardContent, Typography, Button, Grid, TextField, Checkbox, FormControlLabel, CircularProgress, LinearProgress, IconButton } from '@mui/material';
import { AnimatePresence, motion } from 'framer-motion';

const defaultConfig = { nucleiPath: '', templateDir: '', params: {}, selectedTemplates: [], enableAI: false };
const defaultScanStatus = { status: '', code: null, current: '', total: 0, finished: 0, error: '' };

function App() {
  const [error, setError] = useState(null);
  const [config, setConfig] = useState(defaultConfig);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState({ results: [] });
  const [aiResult, setAiResult] = useState({});
  const [scanStatus, setScanStatus] = useState(defaultScanStatus);
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailVuln, setDetailVuln] = useState(null);

  useEffect(() => {
    try {
      console.log('App useEffect start');
      if (!window.api) {
        throw new Error('window.api 不存在，preload.js 未生效');
      }
      window.api.getConfig().then(cfg => {
        console.log('getConfig结果:', cfg);
        cfg && setConfig(cfg);
        // 新增：配置读取后，主动刷新分组
        if (cfg && cfg.templateDir) {
          window.api.getTemplates(cfg.templateDir).then(res => {
            console.log('getTemplates结果:', res);
            setTemplates(res);
          }).catch(e => {
            setError('getTemplates异常: ' + e);
            console.error('getTemplates异常:', e);
          });
        }
      }).catch(e => {
        setError('getConfig异常: ' + e);
        console.error('getConfig异常:', e);
      });
      // 注册扫描进度事件
      window.api.onScanProgress((statusObj) => {
        setScanStatus(prev => ({ ...prev, ...statusObj }));
      });
    } catch (e) {
      setError('useEffect异常: ' + e);
      console.error('useEffect异常:', e);
    }
  }, []);

  const handleConfigChange = (field, value) => {
    setConfig(prev => {
      const newConfig = { ...prev, [field]: value };
      // 路径变更后主动刷新分组
      if (field === 'templateDir' && value) {
        window.api.getTemplates(value).then(res => {
          setTemplates(res);
        }).catch(e => {
          setError('getTemplates异常: ' + e);
        });
      }
      return newConfig;
    });
  };

  const saveConfig = () => {
    // 自动补全并发数和超时时间
    const params = {
      ...config.params,
      concurrency: config.params.concurrency || 50,
      timeout: config.params.timeout || 15
    };
    window.api.setConfig({ ...config, params });
  };

  // 多选文件夹（漏洞类型）
  const handleFolderSelect = (folder) => {
    setConfig(prev => {
      const selected = prev.selectedTemplates.includes(folder)
        ? prev.selectedTemplates.filter(t => t !== folder)
        : [...prev.selectedTemplates, folder];
      return { ...prev, selectedTemplates: selected };
    });
  };

  // 统一的扫描模板目录处理函数
  const handleScanTemplates = async () => {
    if (!config.templateDir) {
      setError('请先选择模板目录');
      return;
    }
    try {
      const templates = await window.api.getTemplates(config.templateDir);
      setTemplates(templates);
      if (templates && templates.length > 0) {
        const selected = templates.map(t => t.name);
        const updatedConfig = { ...config, selectedTemplates: selected };
        setConfig(updatedConfig);
        await window.api.setConfig(updatedConfig);
      }
    } catch (e) {
      setError('扫描模板目录失败: ' + e);
    }
  };

  const runScan = async () => {
    setLoading(true);
    setScanStatus({ ...defaultScanStatus, status: '扫描中', total: config.selectedTemplates.length });
    try {
      // 自动补全并发数和超时时间
      const params = {
        ...config.params,
        concurrency: config.params.concurrency || 50,
        timeout: config.params.timeout || 15,
        enableAI: !!config.enableAI
      };
      const result = await window.api.runNuclei({
        nucleiPath: config.nucleiPath,
        templateDir: config.templateDir,
        params,
        templates: config.selectedTemplates,
        enableAI: !!config.enableAI
      });
      setScanResult(result);
      setScanStatus(prev => ({ ...prev, status: '完成', code: 0 }));
      // AI解释
      for (const vuln of result.results || []) {
        const ai = await window.api.aiExplain(vuln);
        setAiResult(r => ({ ...r, [vuln.id]: ai }));
      }
    } catch (e) {
      setScanStatus(prev => ({ ...prev, status: '异常', error: e.toString(), code: -1 }));
      setLoading(false);
      return;
    }
    setLoading(false);
  };

  const exportResult = async (type) => {
    try {
      const outPath = await window.api.exportResult(scanResult, type);
      window.alert(`导出成功，文件路径：${outPath}`);
    } catch (e) {
      window.alert(`导出失败：${e.toString()}`);
    }
  };

  console.log('App渲染');
  if (error) {
    return <div style={{ color: 'red', padding: 20 }}><h2>前端报错：</h2><pre>{error.toString()}</pre></div>;
  }
  
  return (
    <React.Fragment>
      <style>{`
        body, .MuiTypography-root, .MuiCard-root {
          font-family: '微软雅黑', 'Roboto', 'Arial', sans-serif !important;
        }
        .result-card {
          border-radius: 10px;
          box-shadow: 0 2px 8px #e0e0e0;
          margin-bottom: 12px;
        }
        .ai-explain {
          background: #e3f2fd;
          border-radius: 6px;
          padding: 8px 12px;
        }
        /* 确保按钮始终可见 */
        .action-button {
          display: inline-flex !important;
          visibility: visible !important;
          opacity: 1 !important;
          position: static !important;
        }
      `}</style>
      
      <Box sx={{ p: 3, maxWidth: '100%', overflowX: 'hidden' }}>
        {/* 配置卡片 */}
        <Card sx={{ mb: 3, boxShadow: 3 }}>
          <CardContent>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={6}>
                <TextField 
                  label="Nuclei 路径 (exe)" 
                  fullWidth 
                  value={config.nucleiPath} 
                  onChange={e => handleConfigChange('nucleiPath', e.target.value)} 
                  onBlur={saveConfig}
                  InputProps={{
                    endAdornment: (
                      <IconButton onClick={async () => {
                        const filePath = await window.api.selectFile('exe');
                        if (filePath) {
                          handleConfigChange('nucleiPath', filePath);
                          saveConfig();
                        }
                      }}>
                        <span role="img" aria-label="文件">📁</span>
                      </IconButton>
                    )
                  }}
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                  <TextField 
                    label="模板目录 (文件夹)" 
                    fullWidth 
                    value={config.templateDir} 
                    onChange={e => handleConfigChange('templateDir', e.target.value)} 
                    onBlur={saveConfig} 
                  />
                  <IconButton onClick={async () => {
                    const folderPath = await window.api.selectFolder();
                    if (folderPath) {
                      const newConfig = { ...config, templateDir: folderPath };
                      setConfig(newConfig);
                      await window.api.setConfig(newConfig);
                    }
                  }}>
                    <span role="img" aria-label="文件夹">📁</span>
                  </IconButton>
                </Box>
              </Grid>
              
              <Grid item xs={12} md={6}>
                <TextField 
                  label="目标URL" 
                  fullWidth 
                  value={config.params.url || ''} 
                  onChange={e => handleConfigChange('params', { ...config.params, url: e.target.value })} 
                  placeholder="http://example.com" 
                />
              </Grid>
              
              <Grid item xs={6} md={3}>
                <TextField 
                  label="并发数 -c" 
                  type="number" 
                  inputProps={{ min: 1, max: 200 }} 
                  value={config.params.concurrency || 50} 
                  onChange={e => handleConfigChange('params', { ...config.params, concurrency: Number(e.target.value) })} 
                />
              </Grid>
              
              <Grid item xs={6} md={3}>
                <TextField 
                  label="超时时间 -timeout" 
                  type="number" 
                  inputProps={{ min: 1, max: 120 }} 
                  value={config.params.timeout || 15} 
                  onChange={e => handleConfigChange('params', { ...config.params, timeout: Number(e.target.value) })} 
                />
              </Grid>
              
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={<Checkbox 
                    checked={!!config.enableAI} 
                    onChange={async e => {
                      const checked = e.target.checked;
                      if (checked) {
                        if (window.api && window.api.checkAIAvailable) {
                          const ok = await window.api.checkAIAvailable();
                          if (!ok) {
                            window.alert('AI接口不可用，请检查API KEY和网络！');
                            return;
                          }
                        }
                      }
                      handleConfigChange('enableAI', checked);
                      window.api.setConfig({ ...config, enableAI: checked });
                    }} 
                  />}
                  label="启用AI解释"
                />
              </Grid>
            </Grid>
          </CardContent>
        </Card>
        
        {/* 模板选择卡片 */}
        <Card sx={{ mb: 3, boxShadow: 3 }}>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>漏洞分组分类选择</Typography>
            {(() => {
              const groupMap = {};
              templates.forEach(cat => {
                if (!groupMap[cat.group]) groupMap[cat.group] = [];
                groupMap[cat.group].push(cat.name);
              });
              return Object.entries(groupMap).map(([group, folders]) => (
                <Box key={group} sx={{ mb: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: '#1976d2' }}>{group}</Typography>
                  <Grid container spacing={1}>
                    {folders.map(folder => (
                      <Grid item key={folder} xs={12} sm={6} md={4} lg={3}>
                        <FormControlLabel
                          control={<Checkbox 
                            checked={config.selectedTemplates.includes(folder)} 
                            onChange={() => handleFolderSelect(folder)} 
                          />}
                          label={folder}
                        />
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              ));
            })()}
          </CardContent>
        </Card>
        
        {/* 扫描状态展示 */}
        <Box sx={{ mb: 3 }}>
          {loading && (
            <Card sx={{ mb: 3, bgcolor: '#e3f2fd', boxShadow: 1 }}>
              <CardContent>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, color: '#1976d2' }}>扫描运行中...</Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Typography variant="body2">{scanStatus.status} {scanStatus.current ? `| 当前模板: ${scanStatus.current}` : ''}</Typography>
                  <Typography variant="body2">{scanStatus.finished}/{scanStatus.total !== undefined ? scanStatus.total : '?'}</Typography>
                </Box>
                <Box sx={{ mt: 2 }}>
                  {scanStatus.total > 0 ? (
                    <>
                      <LinearProgress variant="determinate" value={Math.round((scanStatus.finished / scanStatus.total) * 100)} sx={{ height: 8, borderRadius: 4 }} />
                      <Typography variant="caption" sx={{ ml: 1 }}>{Math.round((scanStatus.finished / scanStatus.total) * 100)}%</Typography>
                    </>
                  ) : (
                    <>
                      <LinearProgress variant="indeterminate" sx={{ height: 8, borderRadius: 4 }} />
                      <Typography variant="caption" sx={{ ml: 1 }}>准备中...</Typography>
                    </>
                  )}
                </Box>
                {scanStatus.error && <Typography variant="body2" color="error">异常: {scanStatus.error}</Typography>}
              </CardContent>
            </Card>
          )}
        </Box>
        
        {/* 主要操作按钮区域 - 确保按钮可见 */}
        <Box sx={{ 
          display: 'flex',
          gap: 2,
          mb: 3,
          flexWrap: 'wrap',
          alignItems: 'center',
          minHeight: '60px',
          padding: '8px',
          border: '1px solid #eee',
          borderRadius: 1
        }}>
          <Button
            variant="contained"
            color="primary"
            onClick={runScan}
            disabled={
              loading ||
              !config.nucleiPath ||
              !config.templateDir ||
              !config.params.url ||
              !config.selectedTemplates.length
            }
            className="action-button"
          >
            {loading ? <CircularProgress size={24} /> : '开始扫描'}
          </Button>
          <Button
            variant="outlined"
            color="error"
            disabled={!loading}
            onClick={async () => {
              if (window.api && window.api.abortScan) {
                await window.api.abortScan();
                setLoading(false);
                setScanStatus(prev => ({ ...prev, status: '已打断', code: -2 }));
              }
            }}
            className="action-button"
          >
            打断扫描
          </Button>
          <Button
            variant="contained"
            color="secondary"
            onClick={handleScanTemplates}
            className="action-button"
            sx={{ flexShrink: 0, minWidth: '150px' }}
          >
            一键扫描模板目录
          </Button>
          <Button
            variant="outlined"
            onClick={() => exportResult('html')}
            disabled={!scanResult.results || scanResult.results.length === 0}
            className="action-button"
          >
            导出 HTML
          </Button>
          <Button
            variant="outlined"
            onClick={() => exportResult('json')}
            disabled={!scanResult.results || scanResult.results.length === 0}
            className="action-button"
            sx={{ ml: 1 }}
          >
            导出 JSON
          </Button>
        </Box>
        
        {/* 扫描结果展示 */}
        <AnimatePresence>
          {scanResult && scanResult.results && scanResult.results.length > 0 && (
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <Card sx={{ mt: 3, boxShadow: 3 }}>
                <CardContent>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>扫描结果分组展示</Typography>
                  {(() => {
                    const customSevOrder = ['critical','high','medium','low','info','unknown'];
                    const grouped = {};
                    scanResult.results.forEach(r => {
                      let sev = r.severity;
                      if (!sev && r.raw) {
                        const m = r.raw.match(/\[(critical|high|medium|low|info)\]/i);
                        sev = m ? m[1].toLowerCase() : 'unknown';
                      }
                      if (!grouped[sev]) grouped[sev] = [];
                      grouped[sev].push(r);
                    });
                    return (
                      <>
                        {customSevOrder.map(sev => (
                          grouped[sev] && grouped[sev].length > 0 && (
                            <Box key={sev} sx={{ mb: 3 }}>
                              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: '#d32f2f', mb: 1 }}>{sev.toUpperCase()}</Typography>
                              <Grid container spacing={2}>
                                {grouped[sev].map((r, idx) => (
                                  <Grid item xs={12} md={6} lg={4} key={r.name + r.raw + idx}>
                                    <Card className="result-card" sx={{ bgcolor: '#fff' }}>
                                      <CardContent>
                                        <Typography variant="body1" sx={{ fontWeight: 600 }}>{r.name || r.raw}</Typography>
                                        <Typography variant="body2" color="text.secondary">类型：{r.type || '-'}</Typography>
                                        <Typography variant="body2" color="text.secondary" noWrap>描述：{r.description ? r.description.slice(0, 60) + (r.description.length > 60 ? '...' : '') : '-'}</Typography>
                                        {r.ai?.desc && <div className="ai-explain" style={{maxHeight:60,overflow:'hidden',textOverflow:'ellipsis'}}>{r.ai.desc.slice(0, 60)}{r.ai.desc.length > 60 ? '...' : ''}</div>}
                                        {r.ai?.fix && <div className="ai-explain" style={{background:'#fff3e0',color:'#f57c00',maxHeight:60,overflow:'hidden',textOverflow:'ellipsis'}}>{r.ai.fix.slice(0, 60)}{r.ai.fix.length > 60 ? '...' : ''}</div>}
                                        <Button variant="outlined" size="small" sx={{ mt: 1 }} onClick={() => { setDetailVuln(r); setDetailOpen(true); }}>详细信息</Button>
                                      </CardContent>
                                    </Card>
                                  </Grid>
                                ))}
                              </Grid>
                            </Box>
                          )
                        ))}
                      </>
                    );
                  })()}
                </CardContent>
              </Card>
            </motion.div>
          )}
        </AnimatePresence>
        
        {/* 漏洞详细信息弹窗 */}
        {detailOpen && detailVuln && (
          <Box sx={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', bgcolor: 'rgba(0,0,0,0.25)', zIndex: 9999, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={() => setDetailOpen(false)}>
            <Card sx={{ minWidth: 400, maxWidth: 700, maxHeight: '80vh', boxShadow: 6, display: 'flex', flexDirection: 'column' }} onClick={e => e.stopPropagation()}>
              <CardContent sx={{ overflowY: 'auto', maxHeight: '65vh' }}>
                <Typography variant="h6" sx={{ mb: 2 }}>漏洞详细信息</Typography>
                {Object.entries(detailVuln).map(([k, v]) => (
                  <Box key={k} sx={{ mb: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{k}：</Typography>
                    {k === 'ai' && v && typeof v === 'object' ? (
                      <Box sx={{ bgcolor: '#e3f2fd', p: 2, borderRadius: 2 }}>
                        {v.desc && <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', mb: 1 }}>{v.desc.replace(/\\n/g, '\n')}</Typography>}
                        {v.fix && <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#f57c00', bgcolor: '#fff3e0', p: 1, borderRadius: 1 }}>{v.fix.replace(/\\n/g, '\n')}</Typography>}
                      </Box>
                    ) : (
                      <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{String(v)}</Typography>
                    )}
                  </Box>
                ))}
              </CardContent>
              <Box sx={{ p: 2, borderTop: '1px solid #eee', textAlign: 'right' }}>
                <Button variant="contained" onClick={() => setDetailOpen(false)}>关闭</Button>
              </Box>
            </Card>
          </Box>
        )}
      </Box>
    </React.Fragment>
  );
}

export default App;
    