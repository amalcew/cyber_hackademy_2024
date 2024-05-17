# Diffie-Hellman

Zadanie polegało na odszyfrowaniu flagi wysłanej w pewnym kanale komunikacyjnym. Flaga
została wymieniona pomiędzy uczestnikami czatu w sposób zaszyfrowany, przy wykorzystaniu
pewnej implementacji algorytmu Diffiego-Hellmana, implementującego wymianę kluczy w sposób
bezpieczny.
Algorytm wykorzystuje parę kluczy asymetrycznych, generowanych przy pomocy pewnej pary
parametrów **p** i **g**, gdzie p jest pewną liczba pierwszą, a g pierwiastkiem pierwotnym.
Wygenerowana para kluczy (prywatny i publiczny) pozwala na szyfrowanie informacji przy
pomocy wygenerowanego przy pomocy tych kluczy **współdzielonego sekretu**.

W teorii, znając parametry p, g oraz klucze publiczne obu stron komunikacji, możliwe jest
wygenerowanie klucza prywatnego którejś ze stron, jeśli parametr g jest niewystarczająco dużą
liczbą. Jednakże w przypadku tego zadania, próby złamania szyfrowania z wykorzystaniem
generatora liczb pierwszych jest zbyt skomplikowane obliczeniowo dla dużych liczb.

Uwagę zwraca jednak sposób implementacji funkcji generujących klucz publiczny oraz
współdzielony sekret. Algorytm DH generuje klucze poprzez spotęgowanie odpowiednich liczb i
wykonanie na nich operacji modulo (np. klucz publiczny można zapisać jako gklucz_prywatny mod p). W
kodzie wykorzystany został operator `^`, który w Pythonie jest operacją XOR, a nie potęgowania –
błąd ten sprawia, że operacja generacji klucza, która powinna być operacją nieodwracalną (tzn.
znając klucz publiczny oraz parametry g, p nie da się odtworzyć klucza prywatnego) jest możliwa
do odtworzenia.

Aby odtworzyć klucz prywatny, wystarczy zamienić miejscami strony operacji XOR wewnątrz
funkcji generującej klucz publiczny. Znając klucz prywatny, odtwarzamy współdzielony sekret, a
następnie odszyfrowujemy przy jego pomocy szyfrogram. Podejście prezentuje poniższy kod w
Pythonie, napisany w oparciu o część funkcji z kodu źródłowego DH:

```python
from hashlib import sha256
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
def generate_shared_secret(A, b, p):
return A ^ b % p
def decrypt(secret, data):
secret = sha256(secret.encode('utf8')).digest()
raw = b64decode(data)
cipher = AES.new(secret, AES.MODE_CBC, raw[:AES.block_size])
return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size)
def exploit_public_key(g, A, p):
return g ^ A % p
if __name__ == '__main__':
# pre-shared key
g = 577
p = 10332 ...SNIP... 68943
# Alice's public key
A = 83703 ...SNIP... 19677
# Bob's public key
B = 97559 ...SNIP... 28154
ciphertext = 'UYaG0 ...SNIP... sGg=='
# Alice's reversed private key
a = exploit_public_key(g, A, p)
shared_secret = generate_shared_secret(B, a, p)
plaintext = decrypt(str(shared_secret), ciphertext).decode('utf-8')
print(plaintext) # KPMG{W_Pyth0n13_r0wniez_XOR_t0_n1e_POW@H}
```
---

Kod źródłowy:

DH shared secret generation.py
```python
from hashlib import sha256
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_shared_secret_DH():
    print("Get DH parameters")
    g = int(input('g='))
    p = int(input('p='))
    your_private_key = int(input('Your private key='))
    print('Your public key A is :',generate_public_int(g,your_private_key,p))
    other_public_key = int(input("Other public key="))
    return generate_shared_secret(other_public_key,your_private_key,p)

def generate_public_int(g, a, p):
    return g ^ a % p


def generate_shared_secret(A, b, p):
    return A ^ b % p

def encrypt(secret, data):
    secret = sha256(secret.encode('utf8')).digest()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(secret, AES.MODE_CBC, iv)
    return b64encode(iv + cipher.encrypt(pad(data.encode('utf-8'),AES.block_size)))

def decrypt(secret, data):
    secret = sha256(secret.encode('utf8')).digest()
    raw = b64decode(data)
    cipher = AES.new(secret, AES.MODE_CBC, raw[:AES.block_size])
    return unpad(cipher.decrypt(raw[AES.block_size:]), AES.block_size)


if __name__ == '__main__':
    
    shared_secret = str(generate_shared_secret_DH())
    

    while True:
        print ("""
        1.Encrypt
        2.Decrypt
        3.Exit
        """)
        ans=input("Option=") 
        if ans=="1": 
            print('ENCRYPTION')
            msg = input('Text to encrypt: ')
            print('Ciphertext:', encrypt(shared_secret,msg).decode('utf-8'))
        elif ans=="2":
            print('\nDECRYPTION')
            cte = input('Ciphertext: ')
            print('Decryped text:', decrypt(shared_secret,cte).decode('utf-8'))
        elif ans=="3":
            exit()
```

chat.txt:
```
Alicja: Hej, udało mi się zdobyć kolejną flagę z H@ckademy
Bob: O, podeślij plis
Alicja: Spoko, tylko na wszelki wypadek ją zaszyfruję, kto wie kto może podsłuchiwać.
Bob: Ok
Alicja: Użyjmy naszego niezawodnego skryptu do wymiany sekretów. No ten Diffie Helman.
Bob: Ah, nasz pierwszy projekt w Pytongu. 
Alicja: Dobra wysyłam dane:
	g=577
	p=10332921861938291919377635159012636040519117927041835671194203494937679183911345052843111512544303969800681115505917911462916407940308340306260755239268943
	A=8370337962458643162004582468469045984889816058567658904788530882468973454873284491037710219222503893094363658486261941098330951794393018216763327572119677
Bob: B=9755909033513767641159594933585734179714892615169429957597029280980531443144704341694474385957669949989090202320232433789032328934018623049865998847328154
Alicja: Łap zaszyfrowaną flagę.
UYaG0KR+k8SmDn9ag/LV9u8h76iXpy6n5D7u00Y3rU/+suuGWSvm6J1ajXO2HxGgt6gyDFtNUZnsgfxGBAysGg==
Bob: Dzięki wielkie. Dzięki naszej bezbłędnej implementacji Diffie Helmana nie ma szans żeby ktoś ją rozszyfrował hehe
```
