# Active Directory

```
Podczas testu penetracyjnego infrastruktury Active Directory u klienta wykorzystałeś popularny program SharpHound v2.3.2 (https://github.com/BloodHoundAD/SharpHound) do zebrania wszystkich informacji o domenie. Plik sharphound.zip, będący wynikiem działania programu jest do Twojej dyspozycji. W Twoim interesie leży przeanalizowanie danych w celu odnalezienia ścieżek ataku, które pozwolą na przejęcie domeny Active Directory — uzyskanie dostępu do konta Administratora Domeny. Do tego zadania może Ci się przydać BloodHound (https://github.com/SpecterOps/BloodHound), który przyspieszy proces analizy. Pamiętaj, że im więcej ścieżek ataku znajdziesz, tym lepiej. Postaraj się opisać (wraz z rzutami ekranu) każdą ze ścieżek ze wskazaniem narzędzi służących do przeprowadzenia ataku oraz zwracanych rezultatów.

Punktem startowym do analizy są przejęte konta w wyniku przeprowadzonego ataku Password Spray:

- walker_sutton
- tom_whitney
- coleman_figueroa
- doug_alvarez
- lorena_ingram
- wilda_gibson
- fern_richard
- lionel_boone
- robert_johns
- walker_sutton
- allen_james

Dostęp do tych kont pozwala Ci przeprowadzać ataki, wykorzystując uprawnienia danego użytkownika. Poza tym udało Ci się złamać hasło do jedynego konta serwisowego w domenie ze skonfigurowanym SPN (Service Principal Name) oraz przejąłeś konto administratora lokalnego na komputerze DESKTOP-CG7HRTC.
```

Zadanie zostało wykonane przy użyciu narzędzia Bloodhound CE v5.8.0

Pogrubieniem oznaczone zostały potencjalne wektory ataku na grupę Domain Administrators, gdzie initial footholdem jest konto standardowe, komputer, bądź konto serwisowe.

- walker_sutton
- tom_whitney
- **coleman_figueroa**
- doug_alvarez
- **lorena_ingram**
- **wilda_gibson**
- **fern_richard**
- lionel_boone
- robert_johns
- **allen_james**
- **DESKTOP-CG7HRTC**
- **ITSRV (SPN)**

## COLEMAN_FIGUROA

**Tools**: gpedit GUI

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/1c15fc41-c121-4e68-ad52-739813f1ca17)

### GenericWrite

Przywilej pozwala na modyfikację każdego niechronionego atrybutu docelowego GPO, np. zmianę ustawień grupowych lub zmianę uprawnień dostępu do tego GPO. Posiadając to uprawnienie, możliwe jest modyfikowanie uprawnień OU skupiającego Domain Administrators, co de facto pozwala na przejęcie kontroli nad domeną np. poprzez dodanie nowego użytkownika [Domain Administrators](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#genericwrite-on-group).

#### Zabezpieczenie przed atakiem

Przyznanie tak silnych uprawnień konkretnemu użytkownikowi jest poważnym naruszeniem bezpieczeństwa. Ten rodzaj uprawnień powinien być nadawany tylko i wyłącznie użytkownikom administracyjnym.

## LORENA_INGRAM / FERN_RICHARD

**Tools**: mimikatz/metasploit meterpreter, certify, certutil.exe, Rubeus

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/1335aea3-8f58-4024-aebd-3faeaa864bd3)

### CanRDP

Posiadając dane logowania do użytkowników LORENA_INGRAM lub FERN_RICHARD możliwe jest otworzenie połączenia RDP do komputera CYBER-DC1, przy wykorzystaniu danych logowania jednego z użytkowników, np. przy użyciu natywnego narzędzia mstsc.exe.

Zabezpieczenie przed atakiem

Jeśli z danym komputerem nawiązane jest już inne połączenie RDP nawiązane przez LORENA_INGRAM lub FERN_RICHARD, to połączenie z komputerem zakończy sesję poprzedniego użytkownika na tym urządzeniu. Mechanizm ten powinien być poprawnie odczytany przez wyrzuconego użytkownika oraz zgłoszony do zespołu bezpieczeństwa w celu analizy pod kątem potencjalnego włamania. Istotne jest również wdrożenie odpowiednich systemów klasy SIEM, zdolnych do automatycznego wykrywania podobnych ataków. Warto wspomnieć, że wszelkie połączenia RDP tworzą w logach wydarzenia Logon/Logoff, które mogą pomóc w analizie przez SOC.

Mechanizm RDP jest jednym z fundamentalnych mechanizmów pozwalających na pracę zdalną na serwerze z Windowsem, dlatego głównym sposobem zabezpieczenia się przed atakiem na tym etapie jest przeprowadzenie odpowiednich szkoleń wśród pracowników z zakresu cyberbezpieczeństwa oraz wyczulenie ich na wszelkie podejrzane zachowania infrastruktury AD.

Należy również rozpatrzeć, czy użytkownicy LORENA_INGRAM lub FERN_RICHARD wymagają przywileju bezpośredniego dostępu do komputera CYBER-DC1.

### ExecuteDCOM

Warto zauważyć, że możliwe jest również uzyskanie dostępu do komputera z użytkownika LORENA_INGRAM przy wykorzystaniu mechanizmu DCOM.

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/9600c95e-681d-45ef-94f1-35819bb09ac0)

Znacznie wygodniejsze oraz skuteczniejsze jest jednak uzyskanie bezpośredniego dostępu poprzez RDP.

#### Zabezpieczenie przed atakiem

Głównym sposobem przeciwdziałania atakowi poprzez wykorzystanie mechanizmu jest odpowiednia analiza logów oraz procesów urządzenia pod kątem podejrzanych wydarzeń.

Należy rozpatrzeć, czy użytkownik LORENA_INGRAM wymaga uprawnień pozwalających na wykorzystanie tego mechanizmu.

### HasSession

Dostęp do CYBER-DC1 pozwala na dalszą penetrację sieci klienta. Na komputerze otwarta jest sesja użytkownika ADMINISTRATOR, który jest częścią grupy Domain Administrators.

Przechwycenie danych logowania wymaga dostępu do konta administratora lokalnego na komputerze. Do tego celu może zostać wykorzystane konto użytkownika PHOEBE_GILES (która jest administratorem lokalnym komputera CYBER-DC1), uzyskane ze ścieżki ataku   ALLEN_JAMES (podejście jest jednak nieoptymalne, ponieważ PHOEBE_GILES bezpośrednio należy do Domain Admins, możliwość taka jednak istnieje) lub wykorzystać znaną podatność w celu eskalacji uprawnień bądź wykonania kodu z uprawnieniami administratora, np. [CVE-2023-21768](https://www.pingsafe.com/blog/impact-of-cve-2023-21768-windows-local-privilege-escalation/), wiedząc, że CYBER-DC1 posiada zainstalowany system operacyjny Win Server 2022 SE.

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/fd755fae-6eff-4e61-a279-452c3bd4a9d3)

Przechwycenie hasła wymaga dodatkowo, aby sesja użytkownika nie była sesją typu Network (musi nastąpić moment wprowadzenia przez użytkownika danych logowania). Dane logowania mogą zostać przechwycone przy zastosowaniu narzędzia mimikatz, uruchomione z przywilejem SeDebugPrivilege (umożliwia on uzyskanie dostępu do przestrzeni adresowej innych [procesów](https://devblogs.microsoft.com/oldnewthing/20080314-00/?p=23113). Hasło użytkownika może również zostać przechwycone z clipboarda przy zastosowaniu keyloggerów (np. keyscan_start z frameworka Metasploit).

Możliwe jest również przechwycenie tokenu procesu użytkownika ADMINISTRATOR, bądź “wstrzyknięcie” agenta do istniejącego procesu użytkownika.

Obie metody wymagają aktywnej sesji użytkownika, w czasie gdy przeprowadzany jest atak. Wygodne może być zastosowanie keyloggera, który pozwoli na asynchroniczne przechwycenie sesji.

Uzyskanie dostępu do użtkownika ADMINISTRATOR równoznaczne jest z przejęciem kontroli nad domeną, ponieważ użytkownik ten należy do grupy Domain Administrators.

#### Zabezpieczenie przed atakiem

Głównym sposobem zabezpieczenia przed atakiem w tej ścieżce jest odpowiednie utrzymanie komputera CYBER-DC1, tzn. aktualizacja systemu operacyjnego do najnowszej wersji celem załatania potencjalnych znanych podatności oraz zastosowanie na komputerze programów zabezpieczających EDR (Endpoint Detection and Response).

## WILDA_GIBSON

**Tools**: mimikatz

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/21999b35-455f-44f5-bf0a-9db574402f55)

### DCSync

Użytkownik WILDA_GIBSON posiada przywileje DS-Replication-Get-Changes oraz DS-Replication-Get-Changes-All które umożliwiają na przeprowadzenie ataku DCSync, np. Przy zastosowaniu narzędzia mimikatz (funkcja lsadump::dcsync). Atak ten bazuje na mechanizmie replikacji wewnątrz Active Directory oraz podszywaniu się pod Domain Controller, pozwala na uzyskanie nieuprawnionego dostępu do domeny, np. poprzez zarequestowanie o hash hasła użytkownika KRBTGT. Skuteczne przeprowadzenie tego ataku jest praktycznie jednoznaczne z przejęciem domeny, ponieważ wyciągnięte hashe pozwalają na skuteczne uzyskanie dostępu jako dany użytkownik (np. poprzez wykorzystanie w następnym kroku ataku pass-the-hash, albo Golden Ticket, jeśli wyciągniemy hash hasła użytkownika [KRBTGT](https://adsecurity.org/?p=1729)).

#### Zabezpieczenie przed atakiem

Atak DCSync jest niezwykle trudny do wykrycia. Głównym sposobem minimalizacji ryzyka jest rozsądne przypisywanie przywilejów DS-Replication-Get-Changes oraz DS-Replication-Get-Changes-All odpowiednim użytkownikom, przywileje te powinny być przypisywanie tylko i wyłącznie administratorom.

## ALLEN_JAMES

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/60cff4ca-bb56-404c-bb7c-3af8fb9bc855)

### GenericAll

Użytkownik ALLEN_JAMES posiada przywilej GenericAll nad użytkownikiem PHOEBE_GILES, który posiada przypisaną grupę Domain Administrators. Obecność tego przywileju jest poważnym naruszeniem bezpieczeństwa, z uwagi na fakt że pozwala on na praktycznie dowolną manipulację użytkownikiem docelowym, np. zresetowanie hasła użytkownika przy użyciu modułu PowerView narzędzia PowerSploit (funkcjonalność Set-DomainUserPassword), czy nadpisanie atrybutu “msds-KeyCredentialLink” (z użyciem narzędzia Whisker), który pozwala na autentykację jako dany użytkownik poprzez Kerberos PKINIT.

Przejęcie użytkownika PHOEBE_GILES jest równoznaczne z uzyskaniem dostępu do grupy Domain Administrators.

#### Zabezpieczenie przed atakiem

Przede wszystkim należy rozpatrzyć, czy użytkownik ALLEN_JAMES powinien posiadać tak wysokie uprawnienia względem PHOEBE_GILES. Ten rodzaj uprawnień powinien być nadawany tylko i wyłącznie użytkownikom administracyjnym, jeśli w ogóle – znacznie bezpieczniejsze jest rozdysponowanie odpowiednich uprawnień składających się na GenericAll pomiędzy różnych użytkowników.

## DESKTOP-CG7HRTC

**Tools**: mimikatz/metasploit meterpreter, certify, certutil.exe, Rubeus

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/15e8a5a6-4eda-435c-8e3b-38d5c86efe2a)

### HasSession

Ścieżka wymaga dostępu do konta administracyjnego na komputerze DESKTOP-CG7HRTC, w celu kradzieży hasła/tokenu użytkownika JEREMY_CLARKSON.

Tak, jak w poprzedniej ścieżkce wykorzystującej istniejącą sesję użytkownika (LORENA_INGRAM / FERN_RICHARD), przechwycenie hasła wymaga, aby sesja nie była sesją typu Network. Dane logowania mogą zostać przechwycone przy zastosowaniu narzędzia mimikatz, lub z clipboarda przy zastosowaniu keyloggerów (np. keyscan_start z frameworka Metasploit).

Możliwe jest również przechwycenie tokenu procesu użytkownika JEREMY_CLARKSON, bądź “wstrzyknięcie” agenta do istniejącego procesu użytkownika.

Obie metody wymagają aktywnej sesji użytkownika, w czasie gdy przeprowadzany jest atak.

#### Zabezpieczenie przed atakiem

Skutecznym zabezpieczeniem przeciwko atakowi jest zastosowanie na urządzeniu oprogramowania EDR (Endpoint Detection and Response), które pozwoli na wykrycie potencjalnego zastosowania keyloggerów bądź prób przechwycenia haseł przez mimikatz.

### ADCSESC1

Użytkownik JEREMY_CLARKSON posiada uprawnienia pozwalające na przeprowadzenie ataku ADCS ESC1 na domenie CYBERHACKADEMY.LOCAL, który może posłużyć do złośliwego wygenerowania certyfikatu oraz podszycia się pod inny podmiot, na przykład przy użyciu narzędzia Certify (generowanie cert.) i narzędzia Rubeus (uzyskanie ticketa TGT).

Atak pozwala na podszycie się np. Pod użytkownika posiadającego grupę Domain Administrators, co pozwala na przejęcie domeny.

#### Zabezpieczenie przed atakiem

Głównym sposobem na wykluczenie tego wektora ataku jest odpowiednia konfiguracja Enterprise CA celem usunięcia możliwości nadużywania usługi przez użytkowników o niskich uprawnieniach. Niezbędna jest również taka konfiguracja usługi, aby każda próba wygenerowania certyfikatu wymagała zatwierdzenia przez autoryzowanych użytkowników i/lub menedżerów.

## ITSRV (Service Principal Name)

**Tools**: PowerSploit PowerView/Whisker/impacket,

Przy wykorzystaniu kwerendy CYPHER zlokalizowane zostało konto serwisowe ze skonfigurowanym SPN o nazwie ITSRV@CYBERHACKADEMY.LOCAL

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/af7b9eec-15a3-4ee3-8e02-780f4acc3c20)

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/583997b6-0164-454f-ae41-1bf165456055)

### Owns

Użytkownik serwisowy posiada uprawnienia pozwalające na zarządzanie użytkownikiem ERIK_GUY. Uprawnienia te umożliwiają szeroki wachlarz ataków mających na celu uzyskanie dostępu do użytkownika, jak na przykład nadanie uprawnienia GenericAll użytkownikowi ITSRV nad ERIK_GUY, zrestowanie hasła (PowerSploit PowerView/Whisker) czy nawet atak Kerberoast (impacket).

#### Zabezpieczenie przed atakiem

Próba resetowania hasła może zostać wychwycona przez zespół bezpieczeństwa przy użyciu logów. Użytkownik, któremu zmienione zostaje hasło powinien zgłosić fakt utraty dostępu do swojego konta, dlatego tak ważne jest prowadzenie odpowiednich szkoleń z cyberbezpieczeństwa dla pracowników, aby byli w stanie poprawnie rozpoznać podejrzane zdarzenia. Istotne jest również wdrożenie oprogramowania SIEM zdolnego do automatycznego wykrywania ataków.

W przypadku Kerberoasting, wykrycie tego ataku jest wyjątkowo trudne i może wymagać zastosowania dodatkowego oprogramowania klasy SIEM służące automatycznemu wykrywaniu podejrzanych zdarzeń wewnątrz Active directory.

Jak w powyższych przypadkach, należy również rozpatrzeć, czy nadana własność użytkownikowi ITSRV jest wymagana w świetle potencjalnego zagrożenia przejęcia użytkownika ERIK_GUY.

### AddKeyCredentialLink

Po przejęciu konta ERIK_GUY możliwa jest dalszy ruch horyzontalny w kierunku konta ALLEN_JAMES (do którego zostałe wykradzione już dane logowania, obranie tego kierunku jest nieoptymalne) lub w kierunku komputera CYBER-DC1 poprzez wykorzystanie ataku Shadow Credentials oraz autentykacji przy użyciu Kerberos PKINIT, atak nadpisuje atrybut “msds-KeyCredentialLink” z użyciem narzędzia Whisker.

#### Zabezpieczenie przed atakiem

Aby zmniejszyć ryzyko wystąpienia tego etapu ataku, ważne jest odpowiednie monitorowanie logów pod kątem podejrzanych zdarzeń na komputerze CYBER-DC1.

### HasSession

Dalszy etap ataku penetracyjnego jest tożsamy z opisanym wyżej w podpunkcie HasSession, gdzie celem ataku jest również uzyskanie kontroli nad kontem ADMINISTRATOR.

## Podsumowanie

W przypadku większości ścieżek ataku przejęcie domeny wymaga maksymalnie dwóch “przeskoków” pomiędzy węzłami w AD. Tak łatwa penetracja sieci jest spowodowana wieloma czynnikami, jednak najważniejszym z nich jest nierozważne przydzielanie silnych przywilejów użytkownikom standardowym, które umożliwiają przejęcie kont administracyjnych i skompromitowanie całej domeny. W idealnej konfiguracji, wszelkie przywileje GenericWrite/Ownership i podobne powinny być przypisane tylko i wyłącznie kontom administracyjnym, aby zapobiec jakimkolwiek próbom eskalacji uprawnień przez użytkowników standardowych. Konta administracyjne powinny być traktowane absolutnie priorytetowo, wszelkie użycie kont dokładnie logowane oraz weryfikowane przez zespół bezpieczeństwa. Absolutnie krytyczne jest, aby sesje użytkowników administracyjnych były zamykane w momencie, kiedy działania administracyjne na danym obiekcie zostały zakończone.

Ataki polegające na nieuprawnionym generowaniu certyfikatów są możliwe do wykrycia, jeśli proces jest odpowiednio zarządzany i weryfikowany. Każdy request wygenerowania certyfikatu powinien przechodzić przez weryfikację przez człowieka.

Ważnym jest, aby komputery i serwery były na bieżąco aktualizowane celem łatania podatności, co znacząco utrudni penetrację sieci.
