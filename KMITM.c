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

int verificar_certificado(X509 *cert, const char *nombre_del_servidor) {
    // Verificar la cadena de certificados
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "Error al crear el objeto X509_STORE\n");
        return 0;
    }

    if (X509_STORE_add_cert(store, cert) != 1) {
        fprintf(stderr, "Error al agregar el certificado a la tienda X509_STORE\n");
        X509_STORE_free(store);
        return 0;
    }

    // Verifica la validez del certificado
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error al crear el contexto X509_STORE_CTX\n");
        X509_STORE_free(store);
        return 0;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        fprintf(stderr, "Error al inicializar el contexto X509_STORE_CTX\n");
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return 0;
    }

    if (X509_verify_cert(ctx) != 1) {
        fprintf(stderr, "Fallo en la verificación del certificado: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        return 0;
    }

    // Verifica que el certificado sea válido para el nombre del servidor
    if (nombre_del_servidor) {
        if (X509_check_host(cert, nombre_del_servidor, strlen(nombre_del_servidor), 0, NULL) != 1) {
            fprintf(stderr, "El certificado no es válido para el servidor: %s\n", nombre_del_servidor);
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            return 0;
        }
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    return 1;
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

    // Verificar el certificado y la conexión
    if (!verificar_certificado(cert, nombre_del_servidor)) {
        fprintf(stderr, "No se pudo verificar el certificado del servidor o la conexión no es segura\n");
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
