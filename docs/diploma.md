# ThreatLens — Разработка интеллектуальной системы обнаружения сетевых атак на основе методов машинного обучения

*Выпускная квалификационная работа. Максим Мельников.*

---

## Оглавление

1. [Введение](#1-введение)
2. [Обзор существующих решений](#2-обзор-существующих-решений)
3. [Архитектура системы](#3-архитектура-системы)
4. [Датасет и инженерия признаков](#4-датасет-и-инженерия-признаков)
5. [Модели и результаты](#5-модели-и-результаты)
6. [Explainable AI](#6-explainable-ai)
7. [Ограничения](#7-ограничения)
8. [Перспективы развития](#8-перспективы-развития)
9. [Заключение](#9-заключение)
10. [Ссылки](#10-ссылки)

---

## 1. Введение

### 1.1 Актуальность

Ежегодный отчёт Verizon Data Breach Investigations Report фиксирует, что **≥60% инцидентов** связаны с атаками на сетевом уровне — от горизонтального перемещения внутри периметра до эксфильтрации данных через C2-каналы. Традиционные системы обнаружения вторжений (IDS) строятся вокруг **сигнатурного подхода**: Snort, Suricata и Zeek используют библиотеки заранее заготовленных правил, что приводит к двум фундаментальным проблемам:

1. **Невозможность детекции 0-day атак**: новая угроза, отсутствующая в сигнатурной базе, не регистрируется до появления публичного правила (задержка от часов до недель).
2. **Взрывной рост ложных срабатываний**: при попытке расширить правила до поведенческих паттернов возникают тысячи FP-событий, тонущие в SOC-воркфлоу.

Одновременно в коммерческом сегменте (Darktrace, Vectra AI, ExtraHop) развиваются NDR-решения (Network Detection & Response), использующие ML-классификаторы поверх flow-фич. Они демонстрируют более высокую точность на 0-day угрозах, но остаются закрытыми продуктами с непрозрачной логикой — оператор не видит, по каким признакам принято решение.

### 1.2 Цель работы

Разработать прототип **двух-модульной интеллектуальной системы** обнаружения угроз, объединяющей:

- статический файловый анализ (YARA + heuristic engine + AI-объяснения) для отдельных подозрительных артефактов;
- сетевой модуль — ML-классификатор потоков, обученный на CIC-IDS2017, с двумя видами объяснений (SHAP-вклад фич + естественно-языковое объяснение через LLM).

### 1.3 Задачи

1. Обучить и сравнить несколько моделей (Random Forest, XGBoost, Isolation Forest) на датасете CIC-IDS2017 с использованием 5-fold cross-validation.
2. Сравнить выбранные модели с простыми базовыми алгоритмами (Logistic Regression, Linear SVM, Decision Tree) для обоснования выбора.
3. Реализовать pipeline, извлекающий CIC-IDS2017-совместимые признаки из произвольного PCAP-файла.
4. Предоставить веб-интерфейс с визуализацией результатов (Plotly) и двумя видами объяснимости.
5. Задеплоить в production (threatlens.tech).

---

## 2. Обзор существующих решений

### 2.1 Сигнатурные IDS

| Продукт | Подход | Сильные стороны | Слабости |
|---------|--------|-----------------|----------|
| **Snort** | pattern-matching по payload и заголовкам | большая экосистема правил | только известные атаки; нет ML |
| **Suricata** | multi-threaded Snort-совместимое ядро + Lua-хуки | производительность 10 Gbps+ | по-прежнему требует сигнатур |
| **Zeek (Bro)** | протокольный анализ + DSL-скрипты | глубокое понимание протоколов | не классифицирует атаки сам — нужна надстройка |

Общее ограничение: классификация строится на **точном совпадении** индикаторов, а не на статистике поведения.

### 2.2 ML-ориентированные системы (исследования)

Академические работы на CIC-IDS2017 показывают высокую точность классификации flow-фич:

- Sharafaldin et al. (2018) — первоначальный Random Forest, F1 ~0.96.
- Vinayakumar et al. (2019) — глубокая нейросеть на 78 фичах, F1 ~0.98.
- Abdulhammed et al. (2019) — уменьшение размерности + XGBoost, F1 ~0.99.

Общее замечание: работы фокусируются на **метриках**, но не предоставляют ни воспроизводимого пайплайна до запуска на сыром PCAP, ни **объяснимости** для конечного аналитика.

### 2.3 Коммерческие NDR

Darktrace, Vectra AI, ExtraHop используют комбинацию unsupervised (Isolation Forest, Autoencoders) и supervised моделей. Стоимость — от $50 тыс/год для сегмента SMB, исходный код закрыт, объяснимость минимальная.

### 2.4 Ниша работы

ThreatLens совмещает:
- **Открытую воспроизводимость**: весь pipeline на Python, бенчмарк воспроизводится одной командой.
- **Две модальности объяснимости**: математическая (SHAP) + естественно-языковая (YandexGPT).
- **Двух-модульную архитектуру**: файлы + сеть в одной платформе.

---

## 3. Архитектура системы

### 3.1 Высокоуровневая схема

```
                    +---------------------------------+
                    |   FastAPI web UI + JSON API     |
                    +-----------+---------+-----------+
                                |         |
                +---------------v--+   +--v--------------------+
                | File Analyzer    |   | Network IDS           |
                |------------------|   |-----------------------|
                | YARA (1500+)     |   | cicflowmeter -> 70    |
                | Heuristic engine |   | CIC-IDS2017 features  |
                | PE/OLE/scripts   |   | XGBoost + RF + IForest|
                | SHA256 cache     |   | SHAP explanations     |
                +--------+---------+   +-----------+-----------+
                         |                         |
                         +-----------+-------------+
                                     v
                         +-----------+-----------+
                         | YandexGPT explanation |
                         +-----------------------+
```

### 3.2 Сетевой модуль: детали

PCAP → **парсинг** через `cicflowmeter` (Python-порт оригинального CICFlowMeter) → **70 статистических фич** per-flow → **3 модели параллельно**:

1. **XGBoost** — основной классификатор (14 классов);
2. **Random Forest** — альтернативный классификатор для сравнения и случая недоступности XGBoost;
3. **Isolation Forest** — unsupervised-ветка, обучена только на BENIGN-трафике; предсказывает anomaly score для детекции 0-day.

### 3.3 Пакет `threatlens/`

| Подмодуль | Назначение |
|-----------|------------|
| `analyzers/` | PE / OLE / script / archive парсеры |
| `rules/` | YARA-правила (custom + community) |
| `scoring/` | агрегатор риска файла |
| `heuristics/` | поведенческие профили (stealer / RAT / ransomware / miner / dropper / keylogger) |
| `ml/` | тренировка, фичи, оценка, SHAP |
| `network/` | PCAP → flow → predictions |
| `ai/` | YandexGPT-провайдер + промпты |
| `web/` | FastAPI, шаблоны Jinja2, static (Plotly) |
| `cache.py` | SQLite-кеш результатов файлового анализа |

### 3.4 API

| Endpoint | Метод | Назначение |
|----------|-------|------------|
| `/api/scan` | POST | файловый анализ |
| `/api/network/analyze-pcap` | POST | PCAP → предсказания |
| `/api/network/explain-flow-shap` | POST | top-K SHAP-вкладов для потока |
| `/api/network/explain-flow` | POST | YandexGPT-объяснение потока |
| `/api/lookup/{sha256}` | GET | файловый lookup в кеше |
| `/api/history`, `/api/stats` | GET | история, статистика |

---

## 4. Датасет и инженерия признаков

### 4.1 CIC-IDS2017

Датасет Canadian Institute for Cybersecurity (UNB), 5 дней захваченного трафика корпоративной сети с инъекцией 14 классов атак:

| Класс | Описание |
|-------|----------|
| BENIGN | нормальный трафик |
| DoS Hulk / GoldenEye / slowloris / Slowhttptest | атаки «отказ в обслуживании» |
| Heartbleed | CVE-2014-0160 на OpenSSL |
| DDoS | распределённый DoS (LOIC) |
| PortScan | nmap-сканирование |
| FTP-Patator / SSH-Patator | брутфорс паролей |
| Web Attack – Brute Force / XSS / Sql Injection | атаки web-приложения |
| Bot | C2-коммуникация ботнета |
| Infiltration | боковое перемещение после компрометации |

Общий объём: **2.83 миллиона потоков**, 78 фич + метка.

### 4.2 Feature pipeline

Преобразование реализовано в `threatlens/ml/features.py`:

1. **`VarianceThreshold(0)`** — удаляет 8 признаков с нулевой дисперсией → остаётся **70 фич**.
2. **`StandardScaler`** — приведение к нулевому среднему и единичному std. Критично для `IsolationForest` и `LinearSVC`.
3. **`LabelEncoder`** — преобразует 14 строковых меток в целые 0..13.
4. **`replace([inf, -inf], NaN).fillna(0)`** — защита от численных артефактов в CSV.

Pipeline сохраняется как `feature_pipeline.joblib` и переиспользуется при inference.

### 4.3 Выборка

Для обучения производственных моделей используется **стратифицированная выборка 50 000 потоков** из 2.83M. Обоснование:

- Сохраняет пропорции классов (BENIGN ≈ 80%, остальные 20% поделены между 14 атаками).
- Снижает время CV-прохода с часов до минут без заметной потери F1 (подтверждено на 30K vs 50K vs full).
- Все 14 классов представлены, за исключением Heartbleed (всего 11 потоков в датасете) — этот класс исключается из 5-fold CV автоматически (`n_samples < n_splits`).

### 4.4 Извлечение признаков из сырого PCAP

Для inference на произвольном PCAP используется `cicflowmeter` (pip) — прямой порт оригинального Java CICFlowMeter (которым был создан CIC-IDS2017). В `threatlens/network/flow_extractor.py`:

1. Инициализация `FlowSession` с no-op writer (серверу не нужен CSV-выход).
2. Итерация пакетов через `scapy.PcapReader`, вызов `session.process(pkt)`.
3. `session.garbage_collect(None)` — force-завершение всех потоков.
4. `_map_cicflowmeter_row(data)` — маппинг snake_case имён в Title Case колонки CIC-IDS2017 + перевод времени из секунд в микросекунды (CICFlowMeter-convention).
5. Производные фичи (Subflow, Avg Segment Size, CWE Flag Count) рассчитываются из имеющихся.

Monkey-patching `output_writer_factory` защищён модульным `threading.Lock` — конкурентные запросы в production не ломают друг другу состояние.

---

## 5. Модели и результаты

### 5.1 Конфигурация моделей

| Модель | Гиперпараметры | Обоснование |
|--------|----------------|-------------|
| Random Forest | `n_estimators=100`, `class_weight=balanced`, `max_depth=None` | интерпретируемость, стабильность на несбалансированных классах |
| XGBoost | `n_estimators=200`, `max_depth=8`, `learning_rate=0.1`, `tree_method=hist` | SOTA на tabular данных, быстрое histogram-based обучение |
| Isolation Forest | `n_estimators=200`, `contamination=auto` | unsupervised-ветка, обучение на BENIGN only |

Все модели обучены с `random_state=42` для полной воспроизводимости.

### 5.2 Базовые сравнения (5-fold CV, 30K стратифицированная выборка)

Запуск `python scripts/compare_baselines.py` производит следующую таблицу (`results/cicids2017/baseline_comparison.csv`, график `docs/screenshots/baseline_comparison.png`). Все модели используют одинаковый preprocessing pipeline (StandardScaler + LabelEncoder + VarianceThreshold), одинаковый `random_state=42`, одинаковую 5-fold стратификацию:

| Модель | Accuracy | F1 weighted | Train time, с | Характер |
|--------|----------|-------------|----------------|-------------|
| LogisticRegression | 0.9623 ± 0.0027 | 0.9596 ± 0.0027 | 1.1 | линейный — потолок ~96% |
| LinearSVC | 0.9772 ± 0.0045 | 0.9750 ± 0.0045 | 35.3 | марджинальный классификатор, +1.5% vs LR |
| DecisionTree | 0.9954 ± 0.0010 | 0.9954 ± 0.0010 | 0.4 | нелинейный baseline, быстрее всех |
| Random Forest | 0.9968 ± 0.0009 | 0.9964 ± 0.0011 | 0.5 | ансамбль деревьев, стабильно выше DT |
| **XGBoost** | **0.9979 ± 0.0006** | **0.9978 ± 0.0006** | **2.9** | **производственный выбор** — наименьший CI95 (±0.0005) |

**Вывод**: ансамблевые нелинейные методы (RF, XGBoost) дают прирост **+4% F1** относительно лучшего линейного baseline (LinearSVC). Выбор XGBoost как production-модели обоснован не только средней F1 (+0.14% vs RF), но и более плотным 95%-доверительным интервалом — на защите это значит, что заявление «99.8% F1» статистически надёжнее.

### 5.3 Метрики финальных моделей (train/test 80/20 + 5-fold CV)

Из `results/cicids2017/metrics.json` и `results/cicids2017/cv_results.csv`:

| Модель | Accuracy | Precision | Recall | F1 | F1 CV 5-fold | Train time, с |
|--------|----------|-----------|--------|-----|--------------|----------------|
| RandomForest | 0.9975 | 0.9976 | 0.9975 | 0.9975 | 0.9968 ± 0.0004 | 0.82 |
| **XGBoost** | **0.9983** | **0.9984** | **0.9983** | **0.9983** | **0.9983 ± 0.0003** | **5.14** |
| IsolationForest (binary) | 0.7399 | 0.3657 | 0.4743 | 0.4130 | — | 0.53 |

95%-доверительный интервал для F1 XGBoost: **±0.0003** (очень плотный, 5 fold'ов). Это обосновывает заявление «~99.8% F1» как статистически значимое.

### 5.4 Feature importance

XGBoost gain-based importance (top-20), отражённый в `docs/screenshots/feature_importance.png`:

| Ранг | Признак | Gain |
|------|---------|------|
| 1 | Idle Max | 0.137 |
| 2 | Avg Bwd Segment Size | 0.119 |
| 3 | Bwd Packet Length Std | 0.088 |
| 4 | Total Length of Fwd Packets | 0.068 |
| 5 | act_data_pkt_fwd | 0.055 |
| 6 | Average Packet Size | 0.051 |
| 7 | Subflow Fwd Bytes | 0.030 |
| 8 | Subflow Bwd Packets | 0.028 |
| ... | ... | ... |

Интерпретация: **статистика простоев потока (Idle Max)** и **размеры backward-сегментов** — главные маркеры. Это соответствует природе DoS/DDoS (уникальные простои из-за SYN-flood) и C2-коммуникации (специфичные размеры ответов).

### 5.5 Confusion matrix

На сбалансированном срезе (по 500 потоков каждого класса, всего 9542) получено:

- **DDoS, DoS Hulk, BENIGN** — 99-100% recall;
- **DoS вариации, FTP/SSH-Patator** — 92-98%;
- **PortScan** — 87%;
- **Bot** — 80%;
- **Web Attack, Heartbleed, Infiltration, Sql Injection** — низкий recall: эти классы представлены 11-500 потоками в тренировочной выборке, что ниже порога надёжного обучения.

Визуализация: `docs/screenshots/confusion_matrix.png`.

---

## 6. Explainable AI

Система предоставляет **две дополняющие друг друга** модальности объяснения результатов классификации.

### 6.1 SHAP-объяснения (математическая)

Endpoint `POST /api/network/explain-flow-shap`, реализован в `threatlens/ml/shap_explainer.py`.

Используется `shap.TreeExplainer`, который даёт **точные** (не аппроксимированные) SHAP-значения для древовидных моделей за полиномиальное время.

Для мультикласс-XGBoost форма выхода: `(1, n_features, n_classes)`. Мы берём срез по предсказанному классу, ранжируем фичи по `|SHAP|` и возвращаем топ-K с **signed** значениями:

- Положительные SHAP → признак «тянул» в сторону предсказанного класса;
- Отрицательные SHAP → признак «тянул» против.

UI визуализирует это как горизонтальный bar-chart (красные/синие бары).

### 6.2 LLM-объяснения (текстовая)

Endpoint `POST /api/network/explain-flow`. Используется YandexGPT-Lite (температура 0.3, maxTokens 400). Промпт-шаблон в `threatlens/ai/prompts.py` (`NETWORK_FLOW_PROMPT`) включает:

1. 5-tuple потока и метку;
2. Ключевые статистики (packet counts, byte counts, IAT, флаги, window);
3. Инструкцию вернуть ответ **строго на русском**, до 200 слов, 4 пунктов (что за поведение / по каким признакам / последствия / действие).

**Защита от prompt-injection**:
- IP-адреса проходят regex-валидацию;
- Метка нормализуется (`_normalize_label`) и проверяется против whitelist из 15 канонических классов CIC-IDS2017 (en/em/minus-dashes приводятся к ASCII).

### 6.3 Synergy

На защите демонстрируется: SHAP-график показывает *какие* фичи важны (Init_Win_bytes_forward=29200, SYN Flag Count=2, ...), а LLM-объяснение переводит это в сценарий аналитика («источник совершил SYN-scan на закрытый порт с типичным Linux-окном»).

---

## 7. Ограничения

### 7.1 Feature drift между Java и Python CICFlowMeter

CIC-IDS2017 создан **оригинальным Java CICFlowMeter** от UNB. Мы используем `cicflowmeter` — Python-порт того же алгоритма. Наблюдается остаточный drift:

- В CIC-IDS2017 `SYN Flag Count` часто равен 0 даже для потоков, начинавшихся с SYN-пакета (особенность старой Java-реализации).
- Наш Python-порт корректно считает каждый SYN → расхождение со значениями из CSV.

**Следствие**: метрики 99.8% F1 из таблицы 5.3 справедливы для CIC-IDS2017 CSV; на произвольных third-party PCAP ожидаемая F1 ниже. Пути закрытия задокументированы в `threatlens/network/README.md`.

### 7.2 Малые классы

Heartbleed (11), Infiltration (36), Sql Injection (21) — в CIC-IDS2017 представлены недостаточным для надёжной классификации числом потоков. Модель на них показывает низкий recall. В production рекомендуется либо исключать их из классификатора, либо использовать Isolation Forest как unsupervised-детектор аномалий.

### 7.3 Синтетические тесты

В разделе `tests/test_flow_extractor.py` используются искусственно сгенерированные PCAP (scapy). Из-за feature drift (раздел 7.1) такой трафик может быть классифицирован как BENIGN, даже если имитирует port scan. Регрессия на реальные CIC-IDS2017 строки выполнена в `tests/test_detector.py::test_detector_recognises_portscan_rows_above_threshold`.

### 7.4 Модель не работает с шифрованным трафиком

Фичи CIC-IDS2017 извлекаются до уровня payload (flow statistics + TCP-флаги), поэтому TLS-зашифрованный трафик обрабатывается наравне с открытым. Однако **содержимое** атак web-приложений (XSS, SQLi) в HTTPS не может быть детектировано без TLS-декриптера — это общее ограничение flow-based IDS.

---

## 8. Перспективы развития

| Этап | Описание | Приоритет |
|------|----------|-----------|
| **Live capture** | `scapy.sniff` на интерфейсе, real-time inference через streaming FlowSession | высокий |
| **Retrain на собственном экстракторе** | Применить наш Python-экстрактор к сырым PCAP CIC-IDS2017, переобучить модели — это полностью устранит feature drift (раздел 7.1) | средний |
| **Online learning / drift detection** | Мониторинг дистрибуции фич в production; автоматическое переобучение при концепт-дрейфте | средний |
| **Ansamble decision** | Комбинировать supervised (XGBoost) с unsupervised (Isolation Forest) через stacking — улучшит recall на редких классах | низкий |
| **Адверсариальная устойчивость** | Тестирование на FGSM-подобных атаках на ML-классификатор | низкий |

---

## 9. Заключение

В работе реализован прототип двух-модульной системы обнаружения угроз. Сетевой модуль демонстрирует weighted F1 = 0.998 ± 0.0003 на стандартном бенчмарке CIC-IDS2017, что сопоставимо с лучшими академическими результатами. Ключевые отличия от существующих решений:

1. **Воспроизводимость**: весь pipeline — от загрузки CSV до генерации SHAP-графиков — запускается одной командой и документирован.
2. **Двойная объяснимость**: математическая (SHAP) + естественно-языковая (LLM).
3. **Инженерная зрелость**: 120 автоматических тестов, типизация, строгая валидация входов (защита от prompt-injection), rate limiting, потокобезопасное использование сторонних библиотек.
4. **Открытый стек**: весь код на Python + open-source зависимости; артефакты моделей (16 МБ) версионируются в git для воспроизведения production-окружения.

Система задеплоена по адресу **https://threatlens.tech** и доступна для демонстрации.

---

## 10. Ссылки

1. Sharafaldin I., Lashkari A. H., Ghorbani A. A. *Toward generating a new intrusion detection dataset and intrusion traffic characterization.* ICISSP 2018.
2. Vinayakumar R. et al. *Deep Learning Approach for Intelligent Intrusion Detection System.* IEEE Access 7, 2019.
3. Abdulhammed R. et al. *Deep and machine learning approaches for anomaly-based intrusion detection of imbalanced network traffic.* IEEE Sensors, 2019.
4. Lundberg S. M., Lee S. I. *A Unified Approach to Interpreting Model Predictions.* NeurIPS 2017.
5. CICFlowMeter. https://github.com/ahlashkari/CICFlowMeter
6. Snort. https://www.snort.org/
7. Suricata. https://suricata.io/
8. Zeek. https://zeek.org/
9. Verizon. *2024 Data Breach Investigations Report.* https://www.verizon.com/business/resources/reports/dbir/
10. MITRE ATT&CK Framework. https://attack.mitre.org/

---

## Приложение A — Воспроизведение результатов

```bash
# 1. Скачать CIC-IDS2017 CSV (843 МБ) в data/cicids2017/
#    из https://www.unb.ca/cic/datasets/ids-2017.html

# 2. Установить зависимости
pip install -r requirements.txt

# 3. Обучить все модели + 5-fold CV
python -m threatlens.ml.train --data-dir data/cicids2017 \
    --sample-size 50000 --cv 5 --output results/cicids2017

# 4. Сравнить с baseline'ами
python scripts/compare_baselines.py

# 5. Сгенерировать графики для защиты
python scripts/make_analysis_plots.py
python scripts/make_screenshots.py

# 6. Запустить demo-бенчмарк (F1 на реальных CIC-IDS2017 строках)
python scripts/demo_benchmark.py --per-class 500

# 7. Поднять веб-интерфейс
python -m threatlens.web.app
# -> http://localhost:8888
```

## Приложение B — Структура полезных артефактов

| Файл | Содержание |
|------|------------|
| `results/cicids2017/xgboost.joblib` | production XGBoost (3 МБ) |
| `results/cicids2017/random_forest.joblib` | production RF (12 МБ) |
| `results/cicids2017/isolation_forest.joblib` | production IF (1.4 МБ) |
| `results/cicids2017/feature_pipeline.joblib` | StandardScaler + LabelEncoder + VarianceThreshold |
| `results/cicids2017/metrics.json` | детальные метрики (per-class report, confusion matrix) |
| `results/cicids2017/comparison.csv` | сводная таблица моделей |
| `results/cicids2017/cv_results.csv` | per-fold метрики 5-fold CV |
| `results/cicids2017/baseline_comparison.csv` | базовые сравнения (LR/SVM/DT/RF/XGB) |
| `docs/screenshots/confusion_matrix.png` | 15×15 heatmap, row-normalised |
| `docs/screenshots/feature_importance.png` | top-20 XGBoost gain |
| `docs/screenshots/baseline_comparison.png` | F1 + train time по моделям |
| `docs/screenshots/network_*.png` | Plotly-дашборд |
