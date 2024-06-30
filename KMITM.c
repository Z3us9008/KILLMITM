#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

void imprimir_huella_digital(X509 *cert) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    const EVP_MD *digest = EVP_sha256(); 

    if (X509_digest(cert, digest, md, &n)) {
        printf("Huella digital SHA256 del certificado del servidor: ");
        for (unsigned int i = 0; i < n; i++) {
            printf("%02X%c", md[i], (i + 1 == n) ? '\n' : ':');
        }
    } else {
        fprintf(stderr, "Error al calcular la huella digital del certificado\n");
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
        SSL_CTX_free(ctx);
        return 1;
    }

    if (BIO_do_handshake(bio) <= 0) {
        fprintf(stderr, "Error al establecer la conexión SSL\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        fprintf(stderr, "No se encontró el certificado del servidor\n");
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    imprimir_huella_digital(cert);

    
    long verif = SSL_get_verify_result(ssl);
    if (verif != X509_V_OK) {
        fprintf(stderr, "Fallo en la verificación del certificado: %s\n", X509_verify_cert_error_string(verif));
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    
    unsigned char huella_digital_esperada[] = {
        0x7C, 0xD9, 0x13, 0x50, 0x56, 0x6B, 0x5C, 0xC3,
        0x4E, 0x8F, 0xC4, 0x7A, 0x78, 0x94, 0x8D, 0x9E,
        0x65, 0x3C, 0x97, 0x4A, 0x62, 0xB3, 0x3F, 0x6A,
        0xA3, 0x34, 0xB5, 0x15, 0x4F, 0x2D, 0x19, 0xE1
    };

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n;
    const EVP_MD *digest = EVP_sha256();

    if (!X509_digest(cert, digest, md, &n)) {
        fprintf(stderr, "Error al calcular la huella digital del certificado\n");
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (n != sizeof(huella_digital_esperada) || memcmp(md, huella_digital_esperada, n) != 0) {
        fprintf(stderr, "La huella digital del certificado no coincide con la esperada. Posible ataque MITM.\n");
        X509_free(cert);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("La conexión SSL se estableció correctamente y el certificado del servidor es válido.\n");

    X509_free(cert);
    BIO_free_all(bio);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
