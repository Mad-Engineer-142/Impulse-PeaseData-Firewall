# Impulse PeaceData Firewall
![Alt text](asdf.png "logo")
Impulse PeaceData Firewall - это решение для мониторинга, захвата и модификаии трафика, основонного на кастомных правилах поиска C2 нагрузок.
Или предвещающих данную эксплуатацию факторах.

## Авторы проекта
````
- Иорин Давид 
- Морозов Андрей
- Беляев Иван
 ````
Проект сделан в рамках хакатона КИБХАК @2023 и носит исследовательский характер.

## Проблематика 
Обнаружение C2 трафика в сети сложно из-за использования шифрования, постоянно меняющихся IP и доменов, а также из-за злоумышленников, которые маскируют свои коммуникации под легитимный трафик, используя обычные сервисы и протоколы. Также проблему представляет разнообразие вредоносного ПО, которое может изменять своё поведение, что затрудняет создание эффективных средств обнаружения.


## Архитектура

 Основные компоненты системы:
- ** Pure Python3.10
- ** MITMProxy interface
- ** Pcap File Analyzer
- ** Real-Time Traffic Filter
- ** Sliver CS payload Detector
- ** Database synced with https://feodotracker.abuse.ch

## Описание Архитектуры
- ### Impulse Proxy
  -[CoreMechanic] Представляет собой mitmproxy интерфейс на порте 8080 через который идет трафик. Без правил обработки скорость падает на 5-7% от пиковой производительности. При полной загрузке и максимально возможной оптимизации в условиях хакатона скорость падает на 12-15%.
  -На лету отсеивает запросы с:
   -https://feodotracker.abuse.ch
   - Подозрительными  доменами и поддоменами (типо burpsuite collaborator payload domain)
   - RegXP фильтр по  хедерам
   - По лольному списку IP адрессов
   - Превышающим порог срабатывания Rate Limit Request 

- ### Impulse PcapChecker 
  - Модуль для разгрузки основного прокси. Каждый определенный промежутов времени, весь траффик сохраняется в .pcap файл для параллельного и более ресурсоемкого анализа. Результаты: ip адреса сохраняются в .prx файл ти применяются в файрволл. 

- ### Impulse Telemethry
  - [KillerFeature] Клиент для работы с прокси, суть метода заключается в работе С2 приложений. При работе зараженная машина, при поступлении к ней вредоносного трафика, будет запускать процессы. Отслеживая подозрительные процессы, их время и ip машины, можно опредилить пакет с C2  payload'ом и запомнив его адаптировать файрволл. 

- ### Impulse AI
  - [NotReleased] Не реализованная, но протестированная функция работы с ML для опредения подозрительности зашифрованных TCP пакетов. Причина: Слишком долго и нужна хорошая база реального C2 трафика, что сделать сложно :/ 



