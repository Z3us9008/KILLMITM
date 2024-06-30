# KMITM (Kill the Man in the Middle)

Este programa en C verifica el certificado SSL/TLS de un servidor para detectar posibles ataques "man-in-the-middle" (MITM).

## Requisitos

- gcc
- OpenSSL

### Instalación de OpenSSL en Debian/Ubuntu

Para instalar OpenSSL en sistemas basados en Debian/Ubuntu, usa el siguiente comando:

```bash
sudo apt-get install libssl-dev

Clonación, Compilación y Ejecución del Programa
Clona este repositorio:

bash
Copiar código
git clone https://github.com/Z3us9008/KMITM.git
cd KMITM
Instala las dependencias:

bash
Copiar código
sudo apt-get install libssl-dev
Compila el programa:

bash
Copiar código
gcc -o KMITM check_cert.c -lssl -lcrypto
Ejecuta el programa:

bash
Copiar código
./KMITM www.ejemplo.com
