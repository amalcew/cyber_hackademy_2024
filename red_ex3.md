# Purple Teaming

```
W lutym 2024, dzięki skoordynowanej akcji służb wielu państw, udało się zatrzymać operacje
cybergangu LockBit. Zatrzymań dokonano na terenie Ukrainy oraz Polski. Po udanej akcji, służby
przeprowadziły defacement serwisu, na którym gang publikował dane ofiar.

Na podstawie danych znalezionych w Internecie, zaplanuj ćwiczenie Purple Team, w trakcie którego
będziesz symulował operacje grupy LockBit. Ćwiczenie będzie miało na celu zweryfikowanie czy zespół
SOC klienta jest w stanie wykryć poszczególne etapy cyberataku. Na użytek ćwiczenia, wykorzystamy
standardowy model cyber killchain.

Do każdego z powyższych etapów, znajdź informacje na temat technik, taktyk i procedur grupy LockBit,
które zostały zaobserwowane w historycznych atakach.
```

![Screenshot from 2024-05-17 06-12-36](https://github.com/amalcew/cyber_hackademy/assets/73908014/5dcb1f69-c0eb-44df-8f8c-83a87da482a7)

Grupa przestępcza LockBit swoje działania skupiała na “licencjonowaniu” oprogramowania pozwalającego na przeprowadzanie ataków typu ransomware, w “autorskim” modelu RaaS (ransomware-as-a-service). Ataki ransomware polegają na infekowaniu urządzeń wewnątrz sieci ofiary, a następnie na utrudnieniu bądź całkowitemu zablokowaniu dostępu do danych przechowywanych na tych urządzeniach, w celu uzyskania okupu w zamian za odszyfrowanie danych. Głównym problemem związanym z atakami tego typu jest fakt, iż przestępcy często dokonują ponownej blokady danych, nawet jeśli ofiara zapłaci okup. Przestępcy wykorzystują w tym celu poważne, niezałatane luki w zabezpieczeniach ofiary, bądź pozostawione w czasie pierwszego ataku backdoory.

Grupa nie przeprowadzała ataków samodzielnie, lecz udostępniała narzędzia “zrzeszonym współpracownikom”, czyli osobom trzecim, którym zależało na ataku na konkretną firmę. Z historii grupy wynika, że wiele z ataków przeprowadzonych przy pomocy ich narzędzi były nieskuteczne, bądź przeprowadzone w sposób niedbały. Skutki cyberataku oraz jego powodzenie często zależały od umiejętności osób trzecich.

### Cel

W niniejszym opracowaniu ćwiczeń Purple Team, celem operacji jest przetestowanie zespołu SOC fikcyjnej firmy AppEnture, firmy oferującej konsulting informatyczny dla firm trzecich oraz realizującej projekty informatyczne. Głównym celem ataku są wewnętrzne serwery firmy, hostujące usługi współdzielenia plików, zawierające dane wrażliwe odnośnie pracowników, klientów oraz realizowanych projektów.

Firma **AppEnture** udostępnia swoim pracownikom komputery personalne, które łączą się z intranetem firmy przy wykorzystaniu tunelów wirtualnych oraz tokenów TOTP. Firma AppEnture utworzyła nowy oddział reagowania na ataki typu ransomware mający na celu przeciwdziałanie potencjalnym atakom oraz minimalizacja skutków ataku.

## Cyber killchain

W opracowaniu wykorzystany został framework cyber killchain, opracowany przez korporację Lockheed Martin na potrzeby identyfikacji oraz prewencji ataków w cyberprzestrzeni.

### Reconnaissance

**Lokalizacja**: Internet, sieć wewnętrzna grupy operacyjnej

**Narzędzia**: przykładowe narzędzia OSINTowe: Maltego, Shodan

Niewiele wiadome jest o tym etapie w kontekście grupy LockBit oraz ich współpracowników, można jednak założyć że etap ten nie różnił się od standardowego rekonesansu.

Każde działania operacyjne muszą zostać poprzedzone gruntownym rozpoznaniem celu. Grupa operacyjna będzie starać się zebrać jak najwięcej informacji dostępnych w internecie, takich jak dane pracowników, ich media społecznościowe. Dane te agregowane będą przy pomocy narzędzi automatycznych, np. Maltego, które pozwala na wyszukiwanie danych w sposób zautomatyzowany.

Grupa przy wykorzystaniu wyszukiwarki Shodan będzie starać się wyszukać niezabezpieczone urządzenia sieciowe należące do firmy, które mogą pozwolić na uzyskanie wstępnego dostępu do infrastruktury.

Grupa będzie starać się zebrać jak najwięcej danych  podczas aktywnego skanowania serwerów swojej ofiary.

#### Działania podjęte przez SOC

Aktywne skanowanie infrastruktury z reguły generuje sporo ruchu sieciowego, który jest możliwy do wykrycia przez SOC. Narzędzia takie jak nmap, ffuf, gobuster czy nawet Burp Suite działają w sposób automatyczny wysyłając wiele zapytań na sekundę. Na tym etapie grupa operacyjna sprawdzi, czy SOC poprawnie wykrył podejrzany ruch sieciowy i czy podjął odpowiednie kroki w celu identyfikacji zagrożenia.

### Weaponization

**Lokalizacja**: sieć wewnętrzna grupy operacyjnej

**Narzędzia**: Impacket, Advanced Port Scanner, LaZagne, Mimikatz, AdFind, PsExec, CleanWipe

Współpracownicy grupy LockBit w swoich atakach wykorzystywali przeróżne wektory ataku, takie jak phishing, niepoprawna konfiguracja czy eksploitacja podatności.

W czasie aktywnego rekonesansu grupa operacyjna wykryła miskonfigurację tunelu VPN wykorzystywanego przez pracowników firmy do łączenia się do sieci wewnętrznej firmy. Grupa przygotowuje kampanię phishingową kierowaną do działu rekrutacji, przy wykorzystaniu danych zebranych w czasie rekonesansu. Przygotowywany jest zestaw narzędzi, który posłuży do tworzenia wielu redundantnych backdoorów na systemie Windows oraz serwerach korzystających z protokołu RDP.

Kampania phishingowa polegać będzie na wysłaniu do działu rekrutacji maili zawierających link do pobrania plików wykonywalnych podszywających się pod pliki dokumentów WORD. Po infekcji komputerów pracowników, malware będzie starać się zebrać jak najwięcej danych służących do autoryzacji w tunelach VPN, na stronach dostępnych z poziomu intranetu, będzie starał się skanować sieć w poszukiwaniu dalszych celów.

#### Działania podjęte przez SOC

Z uwagi na fakt, iż ten etap killchaina wykonywany jest głównie po rekonesansie wewnątrz sieci grupy operacyjnej, SOC nie jest w stanie zareagować proaktywnie. W czasie trwania tego etapu może za to przeprowadzać szkolenia z cyberbezpieczeństwa dla pracowników firmy, dokonywać przeglądów raportów podatności, wdrażać nowe procedury przeciwdziałania atakom.

### Delivery

**Lokalizacja**: Internet

**Narzędzia**: protokoły poczty internetowej

Etap rozpoczyna egzekucja kampanii phishingowej. W czasie kampanii rekrutacyjnej firmy AppEnture, rozsyłane są spreparowane maile do pracowników działu kadrowego.

#### Działania podjęte przez SOC

Etap ten jest szczególny ze względu na możliwość uzyskania dostępu przez grupę operacyjną. SOC klienta jest testowany, czy poprawnie reaguje na podejrzenie otrzymania maili phishingowych oraz czy stosuje filtry antyspamowe na serwerach pocztowych. Po wykryciu kampanii phishingowej, SOC powinien niezwłocznie wprowadzić podejrzane domeny mailowe do blacklist w celu zatrzymania kampanii przeciwko pracownikom firmy.

### Exploitation

**Lokalizacja**: Sieć wewnętrzna ofiary (intranet)

**Narzędzia**: Impacket, Advanced Port Scanner, NetScan, LaZagne, Mimikatz, AdFind, PsExec, CleanWipe, RDP, TightVNC, PowerShell

Etap ten jest najlepiej opisany w artykułach dotyczących grupy LockBit oraz case study z historycznych ataków grupy. Jest on również najbardziej rozbudowanym etapem ataku ze względu na wielowektorowość podejmowanych działań przestępczych jak i powtarzanie części kroków killchaina wewnątrz sieci klienta (reconnaissance, lateral movement, privilege escalation itd.)

#### Initial access

Po udanej akcji phishingowej, grupa wykrada dane autoryzujące do tunelu OpenVPN ofiary przy pomocy takich narzędzi, jak LaZagne, Mimikatz. Ze względu na miskonfigurację tunelu, nie jest nałożona whitelista przez co dostęp można uzyskać przy pomocy samych danych autoryzujących oraz wykradzionych certyfikatów X.509. Grupa uzyskuje dostęp do sieci wewnętrznej klienta, przez co rozpoczyna się faza eksploitacji.

#### Mapping internal network & lateral movement

Grupa operacyjna dokonuje rekonesansu sieci, wyszukując więcej urządzeń pracowników oraz serwery przy pomocy skanerów takich jak Advanced Port Scanner, czy NetScan. Horyzontalnie eskalując uprawnienia użytkowników, sieć klienta powoli jest infiltrowana przez grupę, wykradane są hasła, certyfikaty i dane logowania. Ze względu na charakter operacji, nie są usuwane ślady działalności grupy ani nie jest dezaktywowane oprogramowanie antywłamaniowe, efekt ten LockBit uzyskiwało przy użyciu narzędzia CleanWipe. Finalnie uzyskany jest dostęp do serwerów klienta.

#### Działania podjęte przez SOC

Etap ten jest najłatwiejszy do wykrycia przez SOC, ze względu na operowanie grupy wewnątrz monitorowanej sieci klienta. Etap eksploitacji często generuje mnóstwo poszlak, które wykryte przez SOC pozwolą na szybką reakcję i zablokowanie dostępów danych użytkowników, analizę logów, czy aktualizację oprogramowania celem wykluczenia możliwości wykorzystania podatności.

SOC powinien szczególną uwagę zwrócić na wszelkie nowo utworzone konta administracyjne, podejrzany dostęp do danych serwerów, dziwne zachowania stacji roboczych pracowników i tym podobne. Często na tym etapie możliwe jest całkowite zatrzymanie, bądź ograniczenie ataku hakerskiego, zanim doszło do kradzieży danych oraz ich szyfrowania.

### Installation

**Lokalizacja**: Sieć wewnętrzna ofiary (intranet)

**Narzędzia**: PSExec, FileZilla, Rclone, LockBit Encryptor (w wersji wysterylizowanej)

#### Privileges escalation

Po uzyskaniu dostępu do serwerów, następuje krytyczna faza ataku. Tworzone są redundantne backdoory przy zastosowaniu narzędzi RDP, TightVNC, skryptów PowerShell. Grupa operacyjna tworzy konta administracyjne na serwerach domenowych, które pozwolą grupie na łatwiejszy dostęp.

#### Exfiltration

Grupa operacyjna gotowa jest do kradzieży danych z serwerów ofiary oraz instalacji oprogramowania szyfrującego. Ze wzgledu na charakter ćwiczebny scenariusza, wybierane są serwery, które nie są traktowane jako krytyczne przez klienta, np. serwery testowe, czy developerskie. W faktycznym ataku ransomware, LockBit starałby się wybrać serwery zawierające najcenniejsze dane, za które ofiara byłaby skłonna opłacić okup. Historia pokazuje również, że LockBit skupiał się często na pojedynczych serwerach bądź dyskach współdzielonych, zamiast atakować całą infrastrukturę. Wybór krytycznych serwerów skutecznie blokował możliwość prowadzenia działań firmy, skutkując stratami finansowymi.

Grupa operacyjna typuje mało znaczące pliki, docelowo takie, które nie przyniosą klientowi potencjalnych strat finansowych bądź wizerunkowych. Kopiowane są one przy pomocy takich narzędzi jak FileZilla, czy Rclone.

Przy pomocy narzędzia PSExec propagowany jest enkryptor wykorzystywany przez współpracowników LockBita, infekowane są wyznaczone serwery.

#### Execution

Następuje szyfrowanie danych na wytypowanych serwerach. Blokowane są pliki, dyski współdzielone, kopie zapasowe. LockBit w wielu atakach wykorzystywał narzędzia automatyczne do synchronizacji szyfrowania.

#### Działania podjęte przez SOC

Na tym etapie SOC powinien szybko rozpoznać charakter ataku oraz wdrożyć działania mające na celu przeciwdziałanie rozpowszechnianiu ekryptora oraz kradzieży danych firmowych. Zainfekowane serwery muszą zostać jak najszybciej odcięte od reszty urządzeń, wdrożony powinien zostać lockdown mający na celu jak najszybsze zatrzymanie ataku. Etap ten jest najbardziej krytycznym etapem, ponieważ wiele ataków grupy LockBit były wykrywane dopiero na etapie inizjaclizacji szyfrowania. Sprawdzane są również automatyczne systemy defensywne, które mają na celu zmniejszenie powierzchni ataku oraz odratowanie danych.

### Command & Control

**Lokalizacja**: Sieć wewnętrzna ofiary (intranet), Internet

**Narzędzia**: TOR browser, Dark Net

Etap ten jest kojarzony z próbami kontaktu atakującego z ofiarą w celu ustalenia żądań oraz określenia warunków przekazania okupu i dekryptora. LockBit znany jest ze swojej niechlubnej platformy służącej do ujawniania danych wrażliwych oraz do kontaktowania się z ofiarami ataków. Atakujący grozi w tym momencie ofierze ujawnieniem danych oraz przekonuje ofiarę do szybkiej reakcji.

#### Działania podjęte przez SOC

SOC sprawdzany jest pod kątem reagowania na incydent bezpieczeństwa – czy podejmuje próby samodzielnego odszyfrowania danych, czy zatrudnia firmy trzecie specjalizujące się w analizie powłamaniowej. Weryfikowane jest, czy SOC poddaje się żądaniom atakującego. Reakcja SOCu może różnić się w zależności od branży, np. szpitale są bardziej skłonne do zapłacenia okupu niż firmy z sektora prywatnego.

### Actions on Objective

**Lokalizacja**: Sieć wewnętrzna ofiary (intranet), Internet

**Narzędzia**: TOR browser, Dark Net,  RDP, TightVNC

Grupa operacyjna realizuje cel scenariusza, dokonując pełnej infiltracji systemów klienta. Na tym etapie, grupia LockBit po otrzymaniu okupu przekazuje ofierze dekryptory oraz utrzymuje wcześniej nawiązane połączenia i backdoory w celu ponownego ataku w przyszłości.


## Ewaluacja

Po zakończeniu operacji, jeśli nie zostało to ujawnione na poprzednich etapach, ogłaszana jest informacja o ćwiczeniach Purple Team. Grupa operacyjna tworzy rozbudowany raport, który wspomoże SOC klienta w łataniu podatności, tworzeniu nowych protokołów zachowań w razie ataku na każdym z przeprowadzonych etapów. Wszelkie “wykradzione” dane są prezentowane klientowi, wskazywane są wszelkie backdoory oraz połączenia ustanowione w czasie trwania operacji. Należy pamiętać, że przeprowadzona operacja ma na celu sprawdzenie reakcji zespołów cyberbezpieczeństwa, a nie przeprowadzenie ataku – wszystkie działania powinny być legalne oraz przedyskutowane z klientem. Atakujący nie może wykonać żadnych działań mających na celu straty finansowe czy wizerunkowe klienta, dlatego tak ważna jest pełna transparentność i zbieranie dowodów, takich jak screeny, logi z narzędzi penetracyjnych itp.

##### Źródła:

- https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- https://explore.avertium.com/resource/an-avertium-case-study-lockbit
- https://www.varonis.com/blog/anatomy-of-a-ransomware-attack
- https://www.sangfor.com/farsight-labs-threat-intelligence/cybersecurity/lockbit-ransomware-insights-from-4-years-of-tracking
- https://blog.criminalip.io/2022/09/23/lockbit-3-0-ransomware/
- https://www.secureworks.com/blog/lockbit-in-action
