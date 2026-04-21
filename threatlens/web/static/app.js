function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

/* ========== Navigation ========== */
function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    document.getElementById('page-' + name).classList.add('active');
    document.querySelector('[data-page="' + name + '"]').classList.add('active');

    if (name === 'history') loadHistory();
    if (name === 'stats') loadStats();
}

/* ========== File Upload & Scan ========== */
let selectedFile = null;
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const scanBtn = document.getElementById('scanBtn');

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
    e.preventDefault(); dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) { selectedFile = e.dataTransfer.files[0]; updateUploadUI(); }
});
fileInput.addEventListener('change', () => { selectedFile = fileInput.files[0]; updateUploadUI(); });

function updateUploadUI() {
    if (selectedFile) {
        dropZone.innerHTML = '<div class="icon">&#128196;</div><p>' + esc(selectedFile.name) + ' (' + (selectedFile.size / 1024).toFixed(1) + ' КБ)</p>';
        scanBtn.disabled = false;
    }
}

const RISK_LABELS = { LOW: 'НИЗКИЙ', MEDIUM: 'СРЕДНИЙ', HIGH: 'ВЫСОКИЙ', CRITICAL: 'КРИТИЧЕСКИЙ' };
const SUMMARY_RU = {
    'This file is almost certainly malicious.': 'Этот файл почти наверняка вредоносный.',
    'This file shows strong indicators of malicious behavior.': 'Файл демонстрирует явные признаки вредоносного поведения.',
    'This file contains suspicious elements that warrant caution.': 'Файл содержит подозрительные элементы, требующие осторожности.',
    'This file appears to be low risk, but always exercise caution.': 'Файл выглядит безопасным, но всегда соблюдайте осторожность.',
};
const REC_RU = {
    'DELETE this file immediately': 'УДАЛИТЕ этот файл немедленно',
    'Do NOT execute it under any circumstances': 'НЕ запускайте его ни при каких обстоятельствах',
    'If already executed: change all passwords, run full antivirus scan': 'Если уже запускали: смените все пароли, запустите полную проверку антивирусом',
    'Check for unauthorized processes in Task Manager': 'Проверьте диспетчер задач на наличие подозрительных процессов',
    'Do not execute this file': 'Не запускайте этот файл',
    'Consider deleting it': 'Рекомендуется удалить',
    'If you must use it, run in a virtual machine only': 'Если необходимо использовать — только в виртуальной машине',
    'Proceed with caution': 'Действуйте с осторожностью',
    'Verify the source of this file': 'Проверьте источник файла',
    'Consider running in a sandbox before execution': 'Перед запуском рекомендуется проверить в песочнице',
    'File appears safe based on static analysis': 'По результатам статического анализа файл выглядит безопасным',
    'Dynamic behavior may differ — use caution with unknown sources': 'Поведение при запуске может отличаться — будьте осторожны с файлами из неизвестных источников',
};
function tr(text, dict) { return dict[text] || text; }

async function scanFile() {
    if (!selectedFile) return;
    document.getElementById('loading').classList.add('active');
    document.getElementById('result').style.display = 'none';
    scanBtn.disabled = true;

    const formData = new FormData();
    formData.append('file', selectedFile);
    formData.append('ai', document.getElementById('useAI').checked);

    try {
        const resp = await fetch('/api/scan', { method: 'POST', body: formData });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ detail: resp.statusText }));
            throw new Error(err.detail || 'Ошибка сервера');
        }
        const data = await resp.json();
        renderResult(data);
    } catch (err) {
        document.getElementById('result').innerHTML = '<p style="color:#f44336; text-align:center; padding:20px;">' + esc(err.message) + '</p>';
        document.getElementById('result').style.display = 'block';
    }

    document.getElementById('loading').classList.remove('active');
    scanBtn.disabled = false;
}

function renderResult(data) {
    const scoreColor = data.risk_level === 'CRITICAL' ? '#ff1744' : data.risk_level === 'HIGH' ? '#f44336' : data.risk_level === 'MEDIUM' ? '#ff9800' : '#4caf50';
    const riskLabel = RISK_LABELS[data.risk_level] || data.risk_level;

    let html = '<div class="section-title">Информация о файле</div>';
    html += '<table class="info-table">';
    html += '<tr><td>Файл</td><td>' + esc(data.file) + '</td></tr>';
    html += '<tr><td>Размер</td><td>' + data.size.toLocaleString() + ' байт</td></tr>';
    html += '<tr><td>Тип</td><td>' + esc(data.type) + '</td></tr>';
    html += '<tr><td>MD5</td><td class="hash">' + esc(data.md5) + '</td></tr>';
    html += '<tr><td>SHA256</td><td class="hash">' + esc(data.sha256) + '</td></tr>';
    const entNum = Number(data.entropy);
    const entStr = Number.isFinite(entNum) && entNum > 0 ? entNum.toFixed(2) : 'н/д';
    const entVerdict = data.entropy_verdict ? ' (' + esc(data.entropy_verdict) + ')' : '';
    html += '<tr><td>Энтропия</td><td>' + entStr + entVerdict + '</td></tr>';
    html += '</table>';

    html += '<div style="text-align:center">';
    html += '<div class="risk-badge risk-' + data.risk_level + '">' + riskLabel + ' (' + data.risk_score + '/100)</div>';
    html += '<div class="score-bar"><div class="score-fill" style="width:' + data.risk_score + '%;background:' + scoreColor + '"></div></div>';
    html += '<p>' + esc(tr(data.summary, SUMMARY_RU)) + '</p></div>';

    if (data.explanation) {
        html += '<div class="ai-box"><h3>Объяснение</h3>' + esc(data.explanation) + '</div>';
    }

    if (data.findings && data.findings.length > 0) {
        html += '<div class="section-title">Находки (' + data.findings.length + ')</div>';
        html += '<ul class="findings">';
        data.findings.forEach(f => {
            let cls = '';
            const fl = f.toLowerCase();
            if (fl.includes('heuristic') || fl.includes('injection') || fl.includes('keylog') || fl.includes('password')) cls = 'critical';
            else if (fl.includes('network') || fl.includes('persistence')) cls = 'high';
            else if (fl.includes('obfuscation')) cls = 'medium';
            html += '<li class="' + cls + '">' + esc(f) + '</li>';
        });
        html += '</ul>';
    }

    if (data.ai_explanation) {
        html += '<div class="ai-box"><h3>AI-анализ (YandexGPT)</h3>' + esc(data.ai_explanation) + '</div>';
    }

    if (data.recommendations && data.recommendations.length > 0) {
        html += '<div class="section-title">Рекомендации</div>';
        html += '<ul class="recommendations">';
        data.recommendations.forEach(r => html += '<li>&gt; ' + esc(tr(r, REC_RU)) + '</li>');
        html += '</ul>';
    }

    document.getElementById('result').innerHTML = html;
    document.getElementById('result').style.display = 'block';
}

/* ========== History ========== */
async function loadHistory() {
    const el = document.getElementById('historyList');
    el.innerHTML = '<p class="loading-text">Загрузка...</p>';

    try {
        const resp = await fetch('/api/history?limit=50');
        const data = await resp.json();

        if (!data || data.length === 0) {
            el.innerHTML = '<div class="history-empty">Пока нет сканирований. Загрузите файл на вкладке "Сканировать".</div>';
            return;
        }

        let html = '';
        data.forEach(item => {
            const riskColor = item.risk_level === 'CRITICAL' ? '#ff1744' : item.risk_level === 'HIGH' ? '#f44336' : item.risk_level === 'MEDIUM' ? '#ff9800' : '#4caf50';
            const riskLabel = RISK_LABELS[item.risk_level] || item.risk_level;
            const size = item.file_size ? (item.file_size / 1024).toFixed(1) + ' КБ' : '';
            const threat = item.heuristic_type ? ' — ' + item.heuristic_type.toUpperCase() : '';

            html += '<div class="history-item risk-' + item.risk_level + '" onclick="lookupFromHistory(\'' + esc(item.sha256) + '\')">';
            html += '<div><div class="history-file">' + esc(item.file_name || 'unknown') + '</div>';
            html += '<div class="history-meta">' + esc(item.sha256.substring(0, 16)) + '... &middot; ' + size + ' &middot; ' + esc(item.file_type || '') + threat + '</div></div>';
            html += '<div class="history-badge" style="color:' + riskColor + ';border:1px solid ' + riskColor + ';border-radius:12px;">' + riskLabel + ' ' + item.risk_score + '</div>';
            html += '<div class="history-meta">' + (item.scan_count > 1 ? item.scan_count + 'x' : '') + '</div>';
            html += '</div>';
        });
        el.innerHTML = html;
    } catch (err) {
        el.innerHTML = '<p style="color:#f44336;">Ошибка: ' + esc(err.message) + '</p>';
    }
}

function lookupFromHistory(sha256) {
    document.getElementById('lookupInput').value = sha256;
    showPage('lookup');
    lookupHash();
}

/* ========== Lookup ========== */
async function lookupHash() {
    const hash = document.getElementById('lookupInput').value.trim();
    const el = document.getElementById('lookupResult');

    if (!hash) { el.innerHTML = '<p style="color:#888;">Введите SHA256 хеш</p>'; return; }
    if (!/^[0-9a-fA-F]+$/.test(hash)) { el.innerHTML = '<p style="color:#f44336;">Неверный формат хеша</p>'; return; }

    el.innerHTML = '<p class="loading-text">Поиск...</p>';

    try {
        const resp = await fetch('/api/lookup/' + hash);
        if (resp.status === 404) {
            el.innerHTML = '<p style="color:#888; text-align:center; padding:20px;">Хеш не найден в базе. Сначала сканируйте файл.</p>';
            return;
        }
        const data = await resp.json();

        if (data.matches) {
            let html = '<div class="section-title">Найдено ' + data.matches.length + ' совпадений</div>';
            data.matches.forEach(m => {
                html += '<div class="history-item risk-' + m.risk_level + '" onclick="lookupFromHistory(\'' + m.sha256 + '\')">';
                html += '<div class="history-file">' + esc(m.file_name) + '</div>';
                html += '<div class="history-badge" style="color:inherit;">' + m.risk_level + ' ' + m.risk_score + '</div>';
                html += '</div>';
            });
            el.innerHTML = html;
        } else {
            renderResult(data);
            el.innerHTML = document.getElementById('result').innerHTML;
            document.getElementById('result').style.display = 'none';
        }
    } catch (err) {
        el.innerHTML = '<p style="color:#f44336;">Ошибка: ' + esc(err.message) + '</p>';
    }
}

document.getElementById('lookupInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') lookupHash();
});

/* ========== Stats ========== */
async function loadStats() {
    const el = document.getElementById('statsContent');
    el.innerHTML = '<p class="loading-text">Загрузка...</p>';

    try {
        const resp = await fetch('/api/cache-stats');
        const data = await resp.json();

        const total = data.total_files || 0;
        const scans = data.total_scans || 0;
        const hits = data.cache_hits || 0;
        const levels = data.by_risk_level || {};

        let html = '<div class="stats-grid">';
        html += '<div class="stat-card"><div class="stat-number">' + total + '</div><div class="stat-label">Уникальных файлов</div></div>';
        html += '<div class="stat-card"><div class="stat-number">' + scans + '</div><div class="stat-label">Всего сканирований</div></div>';
        html += '<div class="stat-card"><div class="stat-number">' + hits + '</div><div class="stat-label">Из кеша</div></div>';
        html += '</div>';

        if (Object.keys(levels).length > 0) {
            const maxCount = Math.max(...Object.values(levels), 1);
            const colors = { LOW: '#4caf50', MEDIUM: '#ff9800', HIGH: '#f44336', CRITICAL: '#ff1744' };
            html += '<div class="risk-breakdown"><div class="section-title">По уровню риска</div>';
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(level => {
                const count = levels[level] || 0;
                const pct = (count / maxCount * 100).toFixed(0);
                const label = RISK_LABELS[level] || level;
                html += '<div class="risk-bar-row">';
                html += '<div class="risk-bar-label" style="color:' + (colors[level] || '#888') + '">' + label + '</div>';
                html += '<div class="risk-bar-track"><div class="risk-bar-fill" style="width:' + pct + '%;background:' + (colors[level] || '#888') + '"></div></div>';
                html += '<div class="risk-bar-count">' + count + '</div>';
                html += '</div>';
            });
            html += '</div>';
        }

        el.innerHTML = html;
    } catch (err) {
        el.innerHTML = '<p style="color:#f44336;">Ошибка: ' + esc(err.message) + '</p>';
    }
}
