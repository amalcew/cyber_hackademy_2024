# OSINT 

```
W tym zadaniu musisz wykorzystać techniki OSINT (Open Source Intelligence), aby zlokalizować ukryte
flagi. Twoje umiejętności wyszukiwania informacji zostaną poddane próbie, a zadanie to sprawdzi
Twoją zdolność do kreatywnego myślenia oraz efektywnego korzystania z dostępnych narzędzi.
Podkreślamy, że to zadanie obejmuje tylko OSINT pasywny. Kandydaci mogą korzystać wyłącznie z
publicznie dostępnych źródeł danych i nie mogą angażować się w żadne aktywne próby uzyskania
dostępu lub ingerencji w systemy czy sieci.
```
**Dane wejściowe**:
Marlena Daberek

**Format flagi**:
KPMG_RT{s0m3_str1ng}

Zadanie rozpocząłem od prostego wyszukania Marleny Daberek na Google. Pierwszy link prowadzi
na profil na LinkedInie

![1](https://github.com/amalcew/cyber_hackademy/assets/73908014/b9eca369-5924-4589-8698-9dff85290e56)

Mylącym okazał się trop firmy, w której zatrudniona jest poszukiwana osoba, ponieważ poza
wpisami w KRS nie znalazłem żadnych dodatkowych danych o firmie. Znacznie bardziej
wartościowy był jednak link do prywatnej strony, który kierował do Twittera Marleny Daberek:

![2](https://github.com/amalcew/cyber_hackademy/assets/73908014/9458fe5c-f491-4f17-a23b-fc2c40569481)

Interesujące bio, string wygląda jak coś z rodziny Base. Dokładniej jest to tekst zakodowany przy
pomocy base32, uprzednio kodowany szyfrem cezara. Ale poza preferencjami śniadaniowymi
Marleny, nie zdradził on flagi :P

![3](https://github.com/amalcew/cyber_hackademy/assets/73908014/2925c628-6477-4509-9a68-44722a907755)

Znacznie ciekawszy jest jednak ostatni udostępiony post. Treść posta od razu sugeruje w jakim
kierunku należy szukać dalszych informacji. Faktycznie, po chwili poszukiwań znalazłem stronę,
dosłownie wspominaną przez Marlenę:

![4](https://github.com/amalcew/cyber_hackademy/assets/73908014/19d7787e-ee73-47e0-84ae-129d315bcfba)

## Flaga - metadane

Prywatny blog Marleny o kotach nie zawierał dużo informacji, jak i działających komponentów.
Praktycznie żaden z interaktywnych elementów na stronie nie działał jak powinien, co w pewien
sposób sugerowało ścieżkę jaką należy przyjąć – nie skupiać się na funkcjach strony, ale na jej
treści.

![5](https://github.com/amalcew/cyber_hackademy/assets/73908014/cb90b409-580e-418e-b61c-f3c5aebb7dac)

Podejrzany okazał się szablon mema z kotem na stronie MeowMixera – pierwsze dwa wyglądały
normalnie, ale ostatni zdawał się być zdjęciem ekranu, zamiast screenshotem. I to właśnie zdjęcie
zawierało flagę zadania – znajdowała się ona w metadanych zdjęcia, które można łatwo odzyskać
przy pomocy narzędzia **exiftool**.

![6](https://github.com/amalcew/cyber_hackademy/assets/73908014/fd1b7f47-44b9-4311-a051-f0716dbd9f36)

## Flaga - kod źródłowy

Ponieważ strona udostępniona jest w serwisie Github, można założyć, że jej kod źródłowy jest
hostowany na tej samej platformie. Wykorzystując wyszukiwarkę GH oraz ciąg znaków subdomeny
strony internetowej (marldab), który prawdopodobnie jest nazwą użytkownika, trafimy finalnie na
profil użytkownika **marldab**:

![Screenshot from 2024-05-17 05-51-39](https://github.com/amalcew/cyber_hackademy/assets/73908014/d1d82a92-1820-465e-b118-9b10ca725db9)

Użytkownik posiada publiczne [repozytorium](https://github.com/marldab/CatMazing), które okazuje się być kodem źródłowym aplikacji.
Druga flaga znajduje się w pliku index.html (widoczna jest zresztą w kodzie samej strony, można
podejrzeć ją przy wykorzystaniu narzędzi developerskich przeglądarki), zakodowana została przy
pomocy **hex**:

![Screenshot_2024-04-04_12-59-26](https://github.com/amalcew/cyber_hackademy/assets/73908014/04cb12d3-550c-429c-b5c2-fbb7f4fe1c3e)

Można ją bez problemu odczytać, nawet przy pomocy podstawowych narzędzi bashowych:
```bash
echo 4b 50 4d 47 5f 52 54 7b 56 21 45 77 5f 70 34 67 65 5f 24 6f 55 52 43 65 7d | tr -d "[:space:]" | xxd -
r -p
# KPMG_RT{V!Ew_p4ge_$oURCe}%
```

## Flaga - steganografia przy użyciu pliku .mp3

Ciekawą flagą okazała się flaga ukryta w pliku [MeowMeow.mp3](https://github.com/marldab/CatMazing/blob/main/assets/MeowMeow.mp3). Flagę zdradził szum słyszalny w
nagraniu. Otwarcie pliku w narzędziu do analizy spektrum dźwiękowego (**SonicVisualizer**)
zdradził ukrytą flagę widoczną w spektrogramie:

![Screenshot_2024-04-04_12-59-57](https://github.com/amalcew/cyber_hackademy/assets/73908014/4bdb3322-d9e1-43d1-8992-deb3410c3aee)

## Flaga - drugie repozytorium

Użytkownik marldab posiada również drugie repozytorium, w którym znaleźć można parę różnych
hashy i zakodowanych ciągów znaków w base64. Pośród nich znaleźć można [plik zawierajacy
następną flagę](https://github.com/marldab/ClandestineCrate/blob/main/CelestialCoordinates.dat):

![Screenshot from 2024-05-17 05-56-01](https://github.com/amalcew/cyber_hackademy/assets/73908014/efb2ed40-71ed-4e6c-b4fb-d7c46824aea6)

Można ją bez problemu odczytać, nawet przy pomocy podstawowych narzędzi bashowych:

```bash
echo S1BNR19SVHtDTEBuZDMkNzFuM1JlcG99 | base64 -d # KPMG_RT{CL@nd3$71n3Repo}
```
