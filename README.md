# Datagram Transport Layer Security (DTLS)

Datagram Transport Layer Security (DTLS) pruža sigurnost komunikacije za datagrama protokola. DTLS se temelji na Transport Layer Security (TLS) protokol. 
DTLS je dizajniran kako bi bio što sličniji TLS sa minimalnom količinom promjena potrebnih da se riješe problemi nastali iz redoslijeda ili gubitka paketa. TLS zahtjeva pouzdan prijenos podataka, tipično TCP, dok DTLS zahtjeva UDP. DTLS još je poznatiji kao Secure Real Time Transport Protocol, kako nam samo ime kaže koristi se kada je prijenos podatka orijentiran brzini i bez kašnjenja. Najčešće se koristi prilikom real time Multiplayer Online igra, Voice over IP te kako bi se osigurala kontrola prijenosa kanala za razne streaming protokole kao što su DCCP, SCTP i SRTP.
Datagram Transport Layer Security (DTLS) pruža sigurnost komunikacije za datagrame protokola. DTLS se temelji na Transport Layer Security (TLS) protokolu. Transport Layer Security (TLS) je protokol koji omogućuje sigurnu komunikaciju putem interneta, tj. osigurava autentičnost i privatnost komunikacije putem interneta.
	
DTLS je dizajniran kako bi bio što sličniji TLS sa minimalnom količinom promjena potrebnih da se riješe problemi nastali iz redoslijeda ili gubitka paketa. TLS zahtjeva pouzdan prijenos podataka, tipično TCP, dakle ne može se koristiti za nepouzdan prijenos podataka.

Zbog sve većeg broja aplikacija koji su dizajnirani da koriste UDP protokol kao što su multiplayer video igre, Voice over IP, VPN, video konferencije. 

DTLS koristi sve  elemente TLS protokola ali uz određene izmjene koje su nužne zbog činjenice da TLS radi samo preko pouzdanog prijenosnog protokola kao što je TCP,
dok DTLS mora raditi preko nepouzdanog prijenosnog protokola kao što je UDP.



##Instalacija Certifikata

Certificate Authority
openssl req -nodes -x509 -newkey rsa:512 -days 365 -keyout ca-key.pem -out ca-cert.pem

Server Certificate
openssl req -nodes -new -newkey rsa:512 -keyout server-key.pem -out server.csr

Sign Server Certificate
openssl ca -config ca.conf -days 365 -in server.csr -out server-cert.pem

Client Certificate
openssl req -nodes -new -newkey rsa:512 -keyout client-key.pem -out client.csr

Sign Client Certificate
openssl ca -config ca.conf -days 365 -in client.csr -out client-cert.pem



U ca.conf odredili smo neke parametre kao što su duljina trajanja certifikate, ime ključeva i neka opčenita pitanja koja su ugrađena u sam certifikat poput email adrese koje možemo ostaviti „optional“. 

[ ca ]
default_ca = ca_default

[ ca_default ]
dir = ./
certs = $dir
new_certs_dir = $dir
database = ca-db-index
serial = ca-db-serial
RANDFILE = ca-db-rand
certificate = ca-cert.pem
private_key = ca-key.pem
default_days = 365
default_crl_days = 365
default_md = md5
preserve = no
policy = generic_policy

[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

Certifikate moramo spremiti u posebnu mapu certs jer smo tako definirali u samom kodu.
Na arka.foi.hr nalaze se dva primjera: 
Prvi je dtls.test.cpp koji koristi memori BIO, te nam omogućuje simuliranje gubitka paketa pomoču DH parametra. Za kompajliranje koristimo:
$ gcc dtls-test.cpp –lssl –lcrypto –fno –exceptions –o dtls-test


##Dtls_UDP i DTLS_razmjena 

Certifikate moramo spremiti u posebnu mapu certs jer smo tako definirali u samom kodu.
Na arka.foi.hr nalaze se dva primjera: 
Prvi je dtls.test.cpp koji koristi memori BIO, te nam omogućuje simuliranje gubitka paketa pomoču DH parametra. Za kompajliranje koristimo:
$ gcc dtls-trazmjena.cpp –lssl –lcrypto –fno –exceptions –o dtls-test


Drugi primjer naziva je dtls_udp.cpp koji šalje poruke pomoću UDP kanala koristeći DTLS enkripciju. Za komajliranje koristimo:
$ gcc dtls_udp.c -lssl -lcrypto -pthread -o dtls_udp
./dtls_udp – za kreiranje servera (server sluša)




##Primjer rada DTLSA

###ClientHello: 
Klijent  šalje  podržanu   maksimalnu   verziju   DTLS  protokola,   slučajan  broj,
identifikator sjednice, listu predloženih kripto algoritama i listu kompresijskih metoda koje
podržava. Slučajan broj se koristi za zaštitu od ponavljanja poruke.

###HelloVerifyRequest:
Server šalje kolačić radi sprečavanja DOS napada. Klijent je dužan ponoviti kolačić u ClientHello poruci koja slijedi. Poslužitelj šalje ovu poruku kada ne može provjeriti valjanost kolačića kojeg je poslao klijent u prvoj ClientHello poruci ova poruka je opcionalna pa ako se ne koristi onda je tijek dogovaranja identičan TLS-u. 

###ClientHello:
Poruka sadrži sve podatke kao i prva ClienHello poruka, ali ovaj puta sadrži i kolačić koji je server predao unutar HalloVerifyRequest.

###ServerHello:
Server šalje odabranu verziju, algoritme i slučajan broj.

###Certificate: 
Poslužitelj šalje X.509 certifikat koji sadrži RSA javni ključ koji poslužitelj koristi za potpisivanje DH parametra.

###ServerKeyExchange: 
Poslužitelj šalje DH pramtere te tako za počinje DH razmjenu

###CertificateRequest: 
Poslužitelj šalje klijentu zahtjev za njegovim certifikatom. Taj certifikat će klijent koristiti za potpisivanje svojih DH parametra.

###ServerHellpDone:
Ova poruka označava da je to zadnja poruka od poslužitelja u ovom slijedu poruka.

###Certificate: 
Klijent šalje svoj certifikat.
ClientKeyExchange: 
Klijent šalje DH parametre pomoću kojeg će obje strane završiti razmjenu ključeva.

###CertificateVerify:
Klijent šalje potpis svih prethodnih primljenih i poslanih poruka, koristeći svoj tajni ključ.

###ChangeCipherSpec:
Klijent šalje poruku koja označava da je prošlo na upravo odgovorene sigurnosne parametre.

###Finished: 
Klijent šalje poruku koja sadrži MAC svih prethodnih poruka. Poruka je zaštićena s upravo dogovorenim sigurnosnim parametrima.

###ChangeCipherSpec:
Poslužitelj šalje poruku koja označava da je prošao na upravo dogovorene sigurnosne parametre.

###Finished:
Poslužitelj šalje poruku koja sadrži MAC svih prethodnih poruka. Poruka je zastićena s upravo dogovorenim sigurnosnim parametrima
 
