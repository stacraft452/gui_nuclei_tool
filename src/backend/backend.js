// 检查 AI 接口可用性
async function checkAIAvailable() {
  const apiKey = 'your-api-key'; // 建议改为配置项
  try {
    const res = await axios.post('url', { // 这里的URL和KEY需要替换为实际可用的
      model: 'deepseek-chat',
      messages: [{ role: 'user', content: '你好，请简单回复“ok”。' }]
    }, {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    const text = res.data.choices?.[0]?.message?.content || '';
    return text.includes('ok') || text.length > 0;
  } catch {
    return false;
  }
}

exports.checkAIAvailable = checkAIAvailable;
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const axios = require('axios');

// 解析模板目录结构
function getTemplates(templateDir) {
  // 优先使用参数 templateDir，只有参数为空时才读取 config.json
  if (!templateDir) {
    try {
      const configPath = path.join(process.cwd(), 'config.json');
      if (fs.existsSync(configPath)) {
        const raw = fs.readFileSync(configPath, 'utf-8');
        const config = JSON.parse(raw);
        templateDir = config.templateDir;
      }
    } catch (e) {
      console.log('[getTemplates] 读取 config.json 异常:', e);
    }
  }
  if (!templateDir || !fs.existsSync(templateDir)) {
    console.log('[getTemplates] 模板目录不存在:', templateDir);
    return [];
  }
  // 只查找一级目录
  const categories = fs.readdirSync(templateDir).filter(f => {
    const full = path.join(templateDir, f);
    return fs.statSync(full).isDirectory();
  });
  if (categories.length === 0) {
    console.log('[getTemplates] 目录下无子文件夹:', templateDir);
    return [];
  }
  // 分组规则
  const groupMap = {
    'Web应用': [
      'web','wordpress','joomla','magento','php','java','javascript','drupal','shopify','laravel','nodejs','graphql','upload','template_injection','remote_code_execution','xss','sql_injection','crlf_injection','cross_site_request_forgery','open_redirect','directory_listing','local_file_inclusion','file','favicon','debug','default','exposed','extract','header','http','config','detect','auth','api','code','cloud','network','passive','perl','python','ruby','sensitive','sharepoint','social','search','subdomain_takeover','vmware','workflows'
    ],
    '数据库': ['mysql','oracle','postgres','mongodb','redis'],
    '中间件': ['nginx','microsoft','apache','cisco','ftp','smtp','rabbitmq','kafka','kong','sap','gcloud','elk','ibm'],
    '协议': ['ssh','samba','ssl','dns'],
    '认证': ['ldap'],
    'CVE': ['cve','cnnvd','cnvd'],
    '其它': []
  };
  // 反向映射：文件夹名->大类
  const folderToGroup = {};
  Object.entries(groupMap).forEach(([group, arr]) => {
    arr.forEach(folder => { folderToGroup[folder] = group; });
  });
  // 动态分组
  const result = categories.map(cat => {
    const templateFiles = fs.readdirSync(path.join(templateDir, cat)).filter(f => f.endsWith('.yaml'));
    return {
      name: cat,
      group: folderToGroup[cat] || '其它',
      templates: templateFiles
    };
  });
  if (result.length === 0) {
    console.log('[getTemplates] 没有分组结果:', templateDir);
  } else {
    console.log('[getTemplates] 返回分组:', result);
  }
  return result;
}

// nuclei 扫描进程管理
let currentNucleiProc = null;

function runNuclei({ nucleiPath, templateDir, params, templates, onProgress }) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const enableAI = params && typeof params.enableAI !== 'undefined' ? params.enableAI : false;
    if (!nucleiPath || !fs.existsSync(nucleiPath)) {
      console.log('[nuclei] Path not found:', nucleiPath);
      if (onProgress) onProgress({ status: '异常', code: -1, error: 'nuclei路径不存在' });
      return resolve([]);
    }
    // 扫描前统计所有选中文件夹下的 .yaml 模板总数
  // 不再递归统计本地yaml文件数，total仅用nuclei输出的模板总数
    // 构造参数数组
    let args = [];
    if (params.url) {
      args.push('-u', params.url);
    }
    if (templates && templates.length > 0) {
      templates.forEach(folder => {
        const folderPath = path.join(templateDir, folder);
        args.push('-t', folderPath);
      });
    }
    if (params.concurrency) args.push('-c', String(params.concurrency));
    if (params.timeout) args.push('-timeout', String(params.timeout));
    if (params.severity) args.push('-severity', params.severity);
    // 强制关闭彩色输出，避免控制字符
    if (!args.includes('-nc')) args.push('-nc');
    console.log('[nuclei] Launching spawn:', nucleiPath, args.join(' '));
    const { spawn } = require('child_process');
  if (onProgress) onProgress({ status: '启动', code: null, current: '', finished: 0 });
    const proc = spawn(nucleiPath, args, { encoding: 'utf-8' });
    currentNucleiProc = proc;
  let buffer = '';
  let allResults = [];
  let dynamicTotal = null;
  // 移除 scan_full_output.txt 文件生成逻辑
  let fullOutputStream = { write: () => {}, end: () => {} };
    function checkExecLine(line) {
      const trimmed = line.trim();
      if (!trimmed) return false;
      // 兼容带颜色码的INF
      const execMatch = trimmed.match(/\[.*INF.*\] Executing (\d+) signed templates/);
      if (execMatch) {
        dynamicTotal = parseInt(execMatch[1], 10);
        if (onProgress) onProgress({ status: '准备扫描', code: 0, current: '', finished: allResults.length, total: dynamicTotal });
        return true;
      }
      return false;
    }
    proc.stdout.on('data', (data) => {
      const str = data.toString('utf-8');
  // fullOutputStream.write(str); // 不再写入 scan_full_output.txt
      buffer += str;
      let lines = buffer.split('\n');
      buffer = lines.pop(); // 保留最后一行（可能未结束）
      for (const line of lines) {
        checkExecLine(line);
        const trimmed = line.trim();
        // 只收集真正漏洞信息：包含等级且不是 WRN/INF/统计类
        if (!/(\[medium\]|\[critical\]|\[low\]|\[high\]|\[info\])/i.test(trimmed)) continue;
        // 只要包含等级字段就收集为漏洞信息，无论格式
        let vuln = { raw: trimmed };
        let ai = { desc: '', fix: '' };
        allResults.push({ ...vuln, ai });
        if (onProgress) onProgress({ status: '扫描中', code: 0, current: vuln.raw, finished: allResults.length, total: dynamicTotal !== null ? dynamicTotal : undefined });
      }
    });
    proc.stderr.on('data', (data) => {
      const str = data.toString('utf-8');
  // fullOutputStream.write(str); // 不再写入 scan_full_output.txt
      let lines = str.split('\n');
      for (const line of lines) {
        checkExecLine(line);
      }
      process.stderr.write(str);
    });
    proc.stderr.on('data', (data) => {
      const str = data.toString('utf-8');
  // fullOutputStream.write(str); // 不再写入 scan_full_output.txt
      process.stderr.write(str);
    });
    proc.on('close', async (code) => {
      currentNucleiProc = null;
  // fullOutputStream.end(); // 不再写入 scan_full_output.txt
      // 自动保存扫描结果到 result 文件夹
      let grouped = {};
      try {
        // 按严重程度分组（无severity则归为unknown）
        for (const r of allResults) {
          const sev = r.severity || 'unknown';
          if (!grouped[sev]) grouped[sev] = [];
          grouped[sev].push(r);
        }
        const resultDir = path.join(process.cwd(), 'result');
        if (!fs.existsSync(resultDir)) fs.mkdirSync(resultDir);
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        const resultPath = path.join(resultDir, `scan_${ts}.json`);
        fs.writeFileSync(resultPath, JSON.stringify({ grouped, results: allResults }, null, 2), 'utf-8');
        console.log('[nuclei] 扫描结果已保存:', resultPath);
      } catch (e) {
        console.log('[nuclei] 保存扫描结果失败:', e);
      }
      // 扫描结束后并发补全AI解释（可选）
      // 修复 exports.aiExplain is not a function 问题，直接引用本文件顶层 aiExplain
      const aiExplain = module.exports.aiExplain;
      if (enableAI && typeof aiExplain === 'function') {
        await Promise.all(allResults.map(async (item, idx) => {
          try {
            const ai = await aiExplain(item);
            item.ai = ai;
            console.log(`[AI] ${item.name || item.raw || idx}:`, ai.desc?.slice(0, 40) || ai.desc);
          } catch (e) {
            item.ai = { desc: '', fix: '' };
            console.log(`[AI] error:`, e);
          }
        }));
      } else {
        allResults.forEach(item => { item.ai = { desc: '', fix: '' }; });
      }
      // 按严重程度分组（无severity则归为unknown）
      const groupedFinal = {};
      for (const r of allResults) {
        const sev = r.severity || 'unknown';
        if (!groupedFinal[sev]) groupedFinal[sev] = [];
        groupedFinal[sev].push(r);
      }
      if (onProgress) onProgress({ status: '完成', code: code, current: '', finished: allResults.length, total: 1 });
      console.log('[nuclei] Scan complete, group count:', Object.keys(groupedFinal).length);
      resolve({ grouped: groupedFinal, results: allResults });
    });
    proc.on('error', (err) => {
      currentNucleiProc = null;
      console.log('[nuclei] Spawn error:', err);
      if (onProgress) onProgress({ status: '异常', code: -1, error: err.message });
      resolve([]);
    });
    console.log('[nuclei] Process started, PID:', proc.pid);
  });
};


// 打断 nuclei 扫描
function abortNucleiScan() {
  if (currentNucleiProc && !currentNucleiProc.killed) {
    try {
      currentNucleiProc.kill('SIGTERM');
      console.log('[nuclei] Scan aborted, PID:', currentNucleiProc.pid);
    } catch (e) {
      console.log('[nuclei] Abort error:', e);
    }
    currentNucleiProc = null;
    return true;
  }
  return false;
}

// AI解释接口（顶层定义，确保导出）
async function aiExplain(vuln) {
  // 这里仅为示例，实际需填入 API KEY
  const apiKey = 'your-api-key'; // 建议改为配置项
  const prompt = `漏洞名称：${vuln.name || ''}\n类型：${vuln.type || ''}\n等级：${vuln.severity || ''}\nURL：${vuln.url || ''}\n描述：${vuln.description || ''}\n请详细解释该漏洞、利用方式和修复建议。`;
  try {
    const res = await axios.post('url', {
      model: 'deepseek-chat',
      messages: [{ role: 'user', content: prompt }]
    }, {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    const text = res.data.choices[0].message.content;
    // 简单分段
    const [desc, fix] = text.split('修复建议：');
    return { desc: desc || text, fix: fix || '' };
  } catch {
    return { desc: '', fix: '' };
  }
}

// 导出结果
function exportResult(data, type) {
  const outPath = path.join(process.cwd(), `scan_result.${type}`);
  if (type === 'json') {
    fs.writeFileSync(outPath, JSON.stringify(data, null, 2));
  } else if (type === 'html') {
    // 分组美化导出
    let html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>漏洞扫描结果</title>
    <style>
      body { font-family: '微软雅黑', 'Roboto', 'Arial', sans-serif; background: #f5f5f5; }
      .group-title { font-size: 1.3em; font-weight: bold; color: #d32f2f; margin-top: 24px; }
      .result-card { background: #fff; border-radius: 10px; box-shadow: 0 2px 8px #e0e0e0; margin: 12px 0; padding: 16px; }
      .ai-explain { background: #e3f2fd; border-radius: 6px; padding: 8px 12px; margin-top: 8px; }
      .ai-fix { background: #fff3e0; color: #f57c00; border-radius: 6px; padding: 8px 12px; margin-top: 8px; }
      .field { margin-bottom: 4px; }
      .raw { color: #888; font-size: 0.95em; margin-top: 4px; }
    </style></head><body><h2>漏洞扫描结果分组展示</h2>`;
    const grouped = data.grouped || {};
    const sevOrder = ['critical','high','medium','low','info','unknown'];
    sevOrder.forEach(sev => {
      if (grouped[sev] && grouped[sev].length > 0) {
        html += `<div class="group-title">${sev.toUpperCase()}</div>`;
        grouped[sev].forEach(r => {
          html += `<div class="result-card">
            <div class="field"><b>名称：</b>${r.name || '-'}</div>
            <div class="field"><b>类型：</b>${r.type || '-'}</div>
            <div class="field"><b>等级：</b>${r.severity || sev}</div>
            <div class="field"><b>URL：</b>${r.url || '-'}</div>
            <div class="raw">${r.raw || ''}</div>
            ${r.ai && r.ai.desc ? `<div class="ai-explain"><b>AI解释：</b>${r.ai.desc}</div>` : ''}
            ${r.ai && r.ai.fix ? `<div class="ai-fix"><b>修复建议：</b>${r.ai.fix}</div>` : ''}
          </div>`;
        });
      }
    });
    html += `</body></html>`;
    fs.writeFileSync(outPath, html);
  }
  return outPath;
}

module.exports = { getTemplates, runNuclei, aiExplain, exportResult, abortNucleiScan };
