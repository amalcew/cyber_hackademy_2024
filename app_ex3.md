# Aplikacja webowa

Zadanie polegało na znalezieniu flagi ukrytej na stronie internetowej H@ckademy KPMG.
Podpowiedzią jest samo polecenie, sugerujące, aby poszukiwania flagi skupić na plikach skryptów
javascript.
W zadaniach tego typu jeśli polecenie nie podaje konkretnego celu poszukiwań, celem okazuje się
zazwyczaj pewien ukryty plik, schowany na stronie internetowej na której znajduje się treść
zadania. Przy pomocy narzędzi programistycznych dostępnych w każdej przeglądarce internetowej
można podejrzeć otrzymane od serwera strony internetowej pliki, w których znalazł się również
plik **riddle.js**

![1](https://github.com/amalcew/cyber_hackademy/assets/73908014/e4e27bc1-3d41-4762-b697-9a1ba7bd455b)

Szybka analiza skryptu wykazała, że porównuje on podany przez użytkownika ciąg znaków z
konkatenacją dwóch odkodowane ciągów znaków oraz pewną wygenerowaną liczbą. Na pierwszy
rzut oka widać, że części flagi zakodowane są przy pomocy algorytmu z rodziny base, potwierdza
to również użycie funkcji atob(). Ostatnim elementem flagi jest pewna liczba, wygenerowana przez
funkcję Random(), którą można łatwo odtworzyć, odczytując składniki działania. Poniższy kod w
js’ie, wyekstraktowany z riddle.js pozwala na odtworzenie flagi:

```js
const encodedStr1 = 'S1BNR3tlQHN5X2J1dF9zdA==';
const encodedStr2 = 'TExfdHIwdWJsM3NfcHBsfQ==';
function Random(seed) {
value = seed * 503 % 701;
return value;
}
str = atob(encodedStr1).concat(Random(570).toString(), atob(encodedStr2))
console.log(str) // KPMG{e@sy_but_st1LL_tr0ubl3s_ppl}
```
