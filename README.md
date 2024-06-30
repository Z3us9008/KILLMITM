# KMITM (Kill the Man in the Middle)

Este programa en C verifica el certificado SSL/TLS de un servidor para detectar posibles ataques "man-in-the-middle" (MITM).

## Requisitos

- gcc
- OpenSSL

### Instalación de OpenSSL en Debian/Ubuntu

Para instalar OpenSSL en sistemas basados en Debian/Ubuntu, usa el siguiente comando:

```bash
sudo apt-get install libssl-dev

```bash
# Clonar el repositorio
git clone https://github.com/Z3us9008/KLLMITM.git

cd KLLMITM

# Instalar dependencias
sudo apt-get install libssl-dev

# Compilar el programa
gcc KMITM.c -o programa -lssl -lcrypto

# Ejecutar el programa
./KMITM www.ejemplo.com
