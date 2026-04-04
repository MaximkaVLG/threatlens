function esc(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
}

let selectedFile = null;

const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const scanBtn = document.getElementById('scanBtn');

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
    e.preventDefault(); dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) { selectedFile = e.dataTransfer.files[0]; updateUI(); }
});
fileInput.addEventListener('change', () => { selectedFile = fileInput.files[0]; updateUI(); });

function updateUI() {
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
        const data = await resp.json();
        renderResult(data);
    } catch (err) {
        document.getElementById('result').innerHTML = '<p style="color:red;">Ошибка: ' + esc(err.message) + '</p>';
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
    html += '<tr><td>Энтропия</td><td>' + data.entropy + ' (' + esc(data.entropy_verdict) + ')</td></tr>';
    html += '</table>';

    html += '<div style="text-align:center">';
    html += '<div class="risk-badge risk-' + data.risk_level + '">' + riskLabel + ' (' + data.risk_score + '/100)</div>';
    html += '<div class="score-bar"><div class="score-fill" style="width:' + data.risk_score + '%;background:' + scoreColor + '"></div></div>';
    html += '<p>' + esc(tr(data.summary, SUMMARY_RU)) + '</p></div>';

    if (data.findings && data.findings.length > 0) {
        html += '<div class="section-title">Находки (' + data.findings.length + ')</div>';
        html += '<ul class="findings">';
        data.findings.forEach(f => {
            let cls = '';
            if (f.toLowerCase().includes('injection') || f.toLowerCase().includes('keylog') || f.toLowerCase().includes('password')) cls = 'critical';
            else if (f.toLowerCase().includes('network') || f.toLowerCase().includes('persistence')) cls = 'high';
            else if (f.toLowerCase().includes('obfuscation')) cls = 'medium';
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
