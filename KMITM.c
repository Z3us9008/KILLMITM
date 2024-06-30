#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

void imprimir_huella_digital(X509 *cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    if (X509_digest(cert, EVP_sha256(), md, &n)) {
        printf("Huella digital: ");
        for (unsigned int i = 0; i < n; i++) {
            printf("%02X%c", md[i], (i + 1 == n) ? '\n' : ':');
        }
    } else {
        fprintf(stderr, "Error al calcular la huella digital\n");
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <nombre_del_servidor>\n", argv[0]);
        return 1;
    }

    const char *nombre_del_servidor = argv[1];

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    const SSL_METHOD *metodo = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(metodo);
    if (!ctx) {
        fprintf(stderr, "No se puede crear el contexto SSL\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    char direccion_bio[256];
    snprintf(direccion_bio, sizeof(direccion_bio), "%s:443", nombre_del_servidor);
    BIO_set_conn_hostname(bio, direccion_bio);

    if (BIO_do_connect(bio) <= 0) {
        fprintf(stderr, "Error al conectar con el servidor\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Error al establecer la conexión SSL\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        imprimir_huella_digital(cert);
        X509_free(cert);
    } else {
        fprintf(stderr, "No se encontró el certificado\n");
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
