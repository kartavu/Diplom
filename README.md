# SDN Traffic Classification using Logistic Regression

Классификация сетевого трафика в программно-определяемых сетях (SDN) с использованием модели машинного обучения Logistic Regression.

## Описание проекта

Цель проекта — автоматическое определение типа сетевого трафика (Ping, DNS, Telnet, Voice, ARP) в реальном времени на основе характеристик потока, собранных SDN-контроллером.

Это позволяет:

- оптимизировать использование сетевых ресурсов,
- повысить производительность сети,
- предотвращать перегрузки,
- не анализировать содержимое пакетов (актуально при использовании шифрования).

## Сравнение с DPI

В традиционных сетях для определения типа трафика часто применяется Deep Packet Inspection (DPI) — метод, анализирующий содержимое пакетов, включая заголовки и полезную нагрузку. Он позволяет:

- точно определять используемые протоколы (HTTP, FTP, DNS и др.),
- различать тип контента (видео, голос, текст),
- распознавать цели (стриминг, звонки, загрузки и т.п.).

Однако DPI имеет ряд ограничений:

- Неэффективен при шифровании — не может анализировать содержимое, если используется HTTPS, VPN и др.
- Требует больших ресурсов — так как нужно обрабатывать каждый пакет.
- Может вызывать вопросы конфиденциальности — заглядывает внутрь передаваемых данных.

Представленная мной система:

- не использует DPI, не анализирует полезную нагрузку,
- основана на flow-level статистике — агрегированных параметрах потока (байты, пакеты, скорость),
- работает в реальном времени и сохраняет высокую точность,
- подходит для анализа зашифрованного трафика, так как использует только метаданные.

- Количество пакетов, переданных за интервал времени:
<img src="results/DPI_vs_ML.png" width="500"/>

- Синий график (с ML) показывает более быстрое накопление вероятности — передача пакетов идёт эффективнее.
- Решение с ML демонстрирует лучшую пропускную способность и более стабильную нагрузку.
- Без ML передача менее равномерна, график нарастает медленно, что указывает на нестабильную обработку трафика.


- Средняя скорость передачи пакетов: 
<img src="results/DPI_vs_ML_speed.png" width="500"/>

- Синий график (с ML) растёт плавно и раньше достигает насыщения — скорость передачи выше и стабильнее.
- Решение без ML показывает резкие скачки и замедленный рост вероятности — трафик обрабатывается менее предсказуемо.
- Нейросеть обеспечивает более равномерную работу даже при высоких нагрузках.



## Архитектура системы

```mermaid
graph TD
    A[Dockerfile] --> B[traffic_classifier_python3.py]
    
    B --> C[simple_monitor_AK.py]
    B --> D[Модель машинного обучения]
    B --> H[Вывод результатов]

    C --> E[Запрос статистики]
    E --> S1[Коммутатор S1]
    S1 --> F[Ответ со статистикой]
    F --> C

    C --> G[строки с данными]
    G --> B

    subgraph Mininet
        S1 --> H1[Хост h1]
        S1 --> H2[Хост h2]
        S1 --> H3[Хост h3]
        S1 --> H4[Хост h4]
    end
```

## Архитектура модели

```mermaid
graph TD
A[Сбор данных] --> B[Предварительная обработка]
B --> C[Нормализация]
B --> D[Очистка данных]
B --> E[Генерация трафика]
E --> F[Разделение набора данных]
F --> G[Обучение модели]
F --> H[Тестирование модели]
G --> I[Алгоритм обучения]
I --> J[Классификация модели]
H --> J
J --> K[Классификация]
```

## Используемые технологии

- **Mininet** — генерация сетевого трафика в виртуальной SDN-среде.
- **SDN-контроллер (Ryu-manager)** — сбор информации о потоках.
- **Python (pandas, scikit-learn)** — обработка данных и обучение модели.
- **Jupyter Notebook** — для прототипирования и визуализации.
- **Dockerfile** - для работы со средой Mininet

## Этапы обработки данных

### 1. Сбор данных
- Сетевая среда моделируется в **Mininet**.
- **SDN-контроллер** фиксирует параметры потоков (MAC-адреса, количество пакетов, статус потока и пр.).
- Данные экспортируются в **CSV** и объединяются в датасет.

### 2. Предварительная обработка
- Удаление пропущенных значений.
- Исключение нерелевантных признаков (например, Forward Packets).
- Нормализация признаков.
- Разделение на обучающую и тестовую выборки (80/20).

### 3. Обучение модели
- Применяется **логистическая регрессия** (Logistic Regression).
- Модель обучается по признакам потока с разметкой типов трафика.
- Оценивается точность на тестовой выборке.

### 4. Оценка результатов
- Строится **матрица ошибок** (confusion matrix).
- Анализируются ошибочные классификации.
- Метрики и данные сохраняются в txt файл

## Структура проекта

```
├── mininet/                           # Dockerfile для настройки и запуска среды Mininet
├── data/                              # CSV-файлы с данными потока
├── notebooks/                         # Jupyter ноутбуки для анализа и обучения
├── models/                            # Сохранённые обученные модели
├── results/                           # Графики, метрики и матрицы ошибок
├── README.md                          # Документация проекта
├── simple_monitor_AK.py               # Приложение Ryu-контроллера: мониторинг потоков и логирование статистики
└── traffic_classifier_python3.py      # Основной скрипт сбора данных и классификации
```

## Используемые признаки для определния типа трафика

| Название признака | Описание |
|-------------------|----------|
| `Forward Packets` | Общее количество пакетов в прямом направлении |
| `Forward Bytes` | Объём байтов в прямом направлении |
| `Delta Forward Packets` | Изменение количества пакетов в прямом направлении |
| `Delta Forward Bytes` | Изменение количества байтов в прямом направлении |
| `Forward Instantaneous Packets per Second` | Мгновенное значение PPS в прямом направлении |
| `Forward Average Packets per Second` | Среднее значение PPS в прямом направлении |
| `Forward Instantaneous Bytes per Second` | Мгновенное значение BPS в прямом направлении |
| `Forward Average Bytes per Second` | Среднее значение BPS в прямом направлении |
| `Reverse Packets` | Общее количество пакетов в обратном направлении |
| `Reverse Bytes` | Объём байтов в обратном направлении |
| `Delta Reverse Packets` | Изменение количества пакетов в обратном направлении |
| `Delta Reverse Bytes` | Изменение количества байтов в обратном направлении |
| `Reverse Instantaneous Packets per Second` | Мгновенное значение PPS в обратном направлении |
| `Reverse Average Packets per Second` | Среднее значение PPS в обратном направлении |
| `Reverse Instantaneous Bytes per Second` | Мгновенное значение BPS в обратном направлении |
| `Reverse Average Bytes per Second` | Среднее значение BPS в обратном направлении |

## Установка и запуск

### 1. Построение Docker-образа с Mininet
```bash
docker build -t mininet-custom .
```

### 2. Запуск контейнера Mininet с пробросом папки проекта
```bash
docker run --rm -it --privileged --net=host -v /Users/mikhailkatsuro/Downloads/diplom:/diplom mininet-custom
```

### 3. Запуск классификатора трафика внутри контейнера
```bash
sudo python3 /Diplom/traffic_classifier_python3.py supervised
```

### 4. Во втором терминале запуск контейнера Mininet
```bash
docker run --rm -it --privileged --net=host mininet-custom
```

### 5. Запуск топологии Mininet
```bash
sudo mn --topo single,2 --controller=remote,ip=127.0.0.1,port=6653 --nat
```

### 6. Генерация трафика между хостами
```bash
h2 ping -c 10 h1
h1 arping -c 5 h2 
h2 sipp -sn uas &
h1 sipp -sn uac h2 &
h2 sudo /usr/sbin/in.telnetd -debug
h2 sudo netstat -tuln | grep ':23'
h1 telnet h2
```

### 7. Тестирование пропускной способности сети
```bash
h1 iperf -s -u &
h2 iperf -c h1 -un 1048576

h1 iperf -s -u -B 224.0.0.251 -p 5353 -i 1 &
h2 iperf -c 224.0.0.251 -u -p 5353 -b 5M -t 20 -i 5 --bind 192.168.1.2

h1 tcpdump -i h1-eth0 -w /tmp/traffic.pcap &
h2 iperf -c 192.168.1.1 -u -b 10M -t 30 -p 5001


apt update && apt install -y git build-essential autoconf libtool libpcap-dev
git clone https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh && ./configure && make

./example/ndpiReader -i /tmp/iperf_udp.pcap -v 1 > results.txt
nano results.txt

h1 iperf -s -B 224.0.0.251 -i1 -u -p 5353 &
h2 iperf -c 224.0.0.251 -i5 -t200 -u -b5m -p 5353 --bind 192.168.1.5


-u - ключ для протокола UDP
по умолчанию TCP
h1 iperf -c 192.168.1.5 -un 1048576
h2 iperf -s -u &

фрагметированный трафик
h1 iperf -c 192.168.1.5 -l 2500 -t 10 -u
h2 iperf -s &

проверить обьем трафика
iperf -c 192.168.1.5 -i1 -u -S 184 -b700M -t99999
```

### Качество классификации
- Матрица ошибок показывает высокую точность классификации типов трафика:
<img src="results/Matrix.png" width="500"/>

### Анализ признаков
- PCA-анализ признаков для визуализации разделимости классов:
<img src="results/Analazy.png" width="500"/>

### Вывод в терминал при работе модели
- Таблица Потоков DNS:
<img src="results/res1.png" width="500"/>
- Таблица Потоков DNS, Voice, Ping:
<img src="results/res2.png" width="500"/>
- Таблица Потоков DNS, Telnet:
<img src="results/res3.png" width="500"/>

### Тестирование пропускной способности сети Без модели
- UDP-тест между двумя хостами: h2 отправляет 1 МБ данных на h1:
<img src="results/test_no_ml.png" width="500"/>
- Multicast-тест: h2 отправляет UDP-трафик 5 Мбит/с на 224.0.0.251, принимается h1.:
<img src="results/test_no_ml_1.png" width="500"/>
- Генерация UDP-нагрузки 10 Мбит/с:
<img src="results/test_no_ml_2.png" width="500"/>
- Анализ трафика: обнаружены UDP-потоки:
<img src="results/test_no_ml_3.png" width="500"/>

### Тестирование пропускной способности сети с моделью
- UDP-тест между двумя хостами: h2 отправляет 1 МБ данных на h1::
<img src="results/test_mininet_with_ml.png" width="500"/>
- Multicast-тест: h2 отправляет UDP-трафик 5 Мбит/с на 224.0.0.251, принимается h1:
<img src="results/test_mininet_with_ml_1.png" width="500"/>
- h1 передаёт 1 МБ UDP-данных на h2:
<img src="results/test_mininet_with_ml_2.png" width="500"/>
- Фрагментированный UDP-трафик: h1 отправляет пакеты по 2500 байт на h2:
<img src="results/test_mininet_with_ml_3.png" width="500"/>

### Полноценные результаты 
- DNS трафик:
<img src="results/output_file1.png" width="500"/>
- Ping трафик:
<img src="results/output_file2.png" width="500"/>
