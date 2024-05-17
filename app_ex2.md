# Aplikacja mobilna

## Flaga 1 - strings.xml

Flaga była ukryta w pliku strings.xml, który przechowuje ciągi znaków wykorzystywane przez
aplikację. Przed odczytaniem flagi niezbędne jest wyekstraktowanie elementów aplikacji np.
poprzez zastosowanie narzędzia **apktool** oraz edytora tekstu, np. Android Studio:

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/9f574a35-6859-4e10-9206-a29e642e3670)

## Flaga 2 - szyfrowanie

W celu ekstrakcji drugiej flagi należy wykorzystać narzędzie **jadx-gui** aby móc podejrzeć kod źródłowy aplikacji. Wewnątrz aktywności MainActivity.class znajduje się instrukcja warunkowa porównująca pewny ciąg znaków podany przez użytkownika z ciągiem wyglądającym jak hash.

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/6c260b4c-d2da-4418-91aa-94a36ffa5e42)

Analiza kodu wykazała, że domniemany hash jest tak naprawdę przekonwertowaną tablicą liczb dziesiętnych w postać hexadecymalną, będącą wynikiem operacji XOR na ciągu znaków podanym przez użytkownika oraz pewnym haśle, trzymanym wewnątrz aplikacji.
Hasło odczytać możemy z **strings.xml**:

![image](https://github.com/amalcew/cyber_hackademy/assets/73908014/8801f390-229a-42ab-92e5-05cbd8f33b44)

Istotne jest spostrzeżenie, że hasło to nie jest odnośnikiem do nazwy aplikacji, ale ciągiem znaków “@string/app_name” poprzedzonym znakiem ucieczki.

W celu ekstrakcji drugiej flagi utworzyłem prosty skrypt w Pythonie, który odtwarza logikę aplikacji oraz brute forceuje odpowiednie znaki ASCII w celu otrzymania końcowej flagi:

```python
import string

alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation

hash = "25393f33080c563b242200422f276327293616442c353a0e211c6c2f443e1e38035900474c3d"
passw = "@string/app_name"

bytes0 = [int(hash[i:i+2], 16) for i in range(0, len(hash), 2)]
bytes2 = [ord(i) for i in passw]
bytes = list()

for i2 in range(len(bytes0)):
    for b in alphabet:
        if ord(b) ^ bytes2[(len(bytes0) - i2 - 1) % len(bytes2)] == bytes0[i2]:
            bytes.append(b)
print(''.join(bytes))  # KPMG{L3VEL_2_FL@G_d0_u_c@r3_4_1_m0r3?}
```

