# ThreatLens ML — Network Intrusion Detection

Модуль для обнаружения сетевых атак методами машинного обучения на датасете CIC-IDS2017.

## Этап 1: Обучение моделей

### Что реализовано

| Компонент | Файл | Описание |
|-----------|------|----------|
| Dataset loader | `dataset.py` | Загрузка CIC-IDS2017 CSV + синтетический генератор |
| Feature pipeline | `features.py` | Очистка, масштабирование, кодирование меток |
| Модели | `models.py` | Random Forest, XGBoost, Isolation Forest |
| Evaluation | `evaluate.py` | Accuracy, Precision, Recall, F1, ROC-AUC, feature importance |
| Training script | `train.py` | Полный пайплайн от датасета до сравнения моделей |

### Архитектура

```
CSV (CIC-IDS2017, 78 flow features)
        |
        v
Dataset loader ---> split_features_labels()
        |                     |
        v                     v
FeaturePipeline (scale, encode)
        |
        v
train_test_split (stratified, 80/20)
        |
        +------+------+
        |      |      |
        v      v      v
      RF   XGBoost  IsolationForest
        |      |      |
        v      v      v
   evaluate_model() -> ModelMetrics
        |      |      |
        +------+------+
               |
               v
       compare_models() -> comparison.csv + metrics.json
```

## Запуск

### 1. Тест на синтетике (без скачивания датасета)

```bash
python -m threatlens.ml.train --synthetic --samples 20000 --output ./results/synthetic
```

Результат на синтетике (20K samples, 6 классов):

| Модель | Accuracy | Precision | Recall | F1 | ROC-AUC |
|--------|----------|-----------|--------|-----|---------|
| RandomForest | 0.9655 | 0.9442 | 0.9655 | 0.9531 | 0.9976 |
| XGBoost | 0.9647 | 0.9545 | 0.9647 | **0.9565** | 0.9976 |
| IsolationForest | 0.8360 | 0.5501 | 0.9888 | 0.7069 | — |

### 2. Реальный датасет CIC-IDS2017

**Шаг 1. Скачать датасет**

Публичные источники:
- Официальный: https://www.unb.ca/cic/datasets/ids-2017.html (требует регистрации)
- Kaggle: https://www.kaggle.com/datasets/cicdataset/cicids2017 (бесплатный аккаунт)

Нужны 8 CSV файлов (~500MB preprocessed, ~50GB в виде PCAP):
- Monday-WorkingHours.pcap_ISCX.csv
- Tuesday-WorkingHours.pcap_ISCX.csv
- Wednesday-workingHours.pcap_ISCX.csv
- Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
- Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
- Friday-WorkingHours-Morning.pcap_ISCX.csv
- Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
- Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

**Шаг 2. Положить в `data/cicids2017/`**

```
threatlens/
├── data/
│   └── cicids2017/
│       ├── Monday-WorkingHours.pcap_ISCX.csv
│       ├── Tuesday-WorkingHours.pcap_ISCX.csv
│       └── ... (всего 8 файлов)
```

**Шаг 3. Обучение**

```bash
# Быстрый тест на 50К сэмплов (~1 минута)
python -m threatlens.ml.train --data-dir ./data/cicids2017 --sample-size 50000

# Полное обучение (~30 минут на CPU)
python -m threatlens.ml.train --data-dir ./data/cicids2017 --balance

# С сохранением в отдельную директорию
python -m threatlens.ml.train --data-dir ./data/cicids2017 --output ./results/cicids2017
```

### Опции

| Флаг | Описание |
|------|----------|
| `--synthetic` | Использовать синтетические данные |
| `--samples N` | Размер синтетической выборки |
| `--data-dir DIR` | Путь к CIC-IDS2017 CSV |
| `--sample-size N` | Стратифицированный подсэмпл реальных данных |
| `--balance` | Downsample BENIGN до медианного размера |
| `--output DIR` | Куда сохранять модели/метрики |
| `--test-size 0.2` | Доля тестовой выборки |

## Артефакты

После запуска в `output/` появятся:

```
results/
├── random_forest.joblib      # Модель RF
├── xgboost.joblib            # Модель XGBoost
├── isolation_forest.joblib   # Модель Isolation Forest
├── feature_pipeline.joblib   # Scaler + LabelEncoder
├── comparison.csv            # Сравнительная таблица
└── metrics.json              # Детальные метрики + per-class report
```

## Использование обученных моделей

```python
import joblib
from threatlens.ml.dataset import load_cicids2017, split_features_labels

# Загрузка
rf = joblib.load("results/random_forest.joblib")
pipeline = joblib.load("results/feature_pipeline.joblib")

# Предсказание на новых данных
df = load_cicids2017("./data/new_traffic/")
X, _, _ = split_features_labels(df)
X_proc, _ = pipeline.transform(X)
predictions = rf.predict(X_proc)
attack_labels = pipeline.inverse_transform_labels(predictions)
```

## Что дальше (Этап 2)

- Feature extraction из живого PCAP через `nfstream`/`scapy`
- API endpoint для загрузки PCAP
- Dashboard с визуализацией детекций
- SHAP explanations для объяснения решений модели
- Интеграция с YandexGPT для описания атак на русском

## Для диплома

**Сравнительный анализ 3 подходов:**
1. **Random Forest** — интерпретируемый baseline
2. **XGBoost** — SOTA на табличных данных (обычно выигрывает по F1)
3. **Isolation Forest** — unsupervised, детектит unknown/0-day атаки

**Метрики для защиты:**
- Accuracy, Precision, Recall, F1 (weighted для multi-class)
- ROC-AUC (one-vs-rest)
- Confusion matrix (per-class ошибки)
- Feature importance (какие фичи определяющие)
- Training/prediction time (практическая применимость)

**Уникальность:**
- Гибридный подход: supervised (точность) + unsupervised (0-day detection)
- Объяснение предсказаний через feature importance (RF/XGB) + SHAP (Этап 4)
- Интеграция с YandexGPT для описания атак (уже работает в файловом модуле)
