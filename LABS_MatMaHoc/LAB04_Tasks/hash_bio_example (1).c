#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// Function to print the hash digest in hexadecimal format
void print_hex(unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    const char *message = "This is the message to hash using OpenSSL BIO";
    BIO *mem_bio = NULL, *md_bio = NULL, *chain_bio = NULL;
    const EVP_MD *digest_type = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char hash_digest[EVP_MAX_MD_SIZE]; // Buffer for the digest
    unsigned int digest_len;

    // Load error strings for better diagnostics (optional but recommended)
    ERR_load_crypto_strings();
    OpenSSL_add_all_digests(); // Register all digest algorithms

    // 1. Get the desired digest algorithm (e.g., SHA-256)
    digest_type = EVP_get_digestbyname("SHA256");
    if (!digest_type) {
        fprintf(stderr, "Error getting digest algorithm.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // 2. Create a digest BIO (filter)
    md_bio = BIO_new(BIO_f_md());
    if (!md_bio) {
        fprintf(stderr, "Error creating digest BIO.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // 3. Set the digest type for the digest BIO
    if (!BIO_set_md(md_bio, digest_type)) {
        fprintf(stderr, "Error setting digest type on BIO.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // 4. Create a memory BIO (source/sink)
    mem_bio = BIO_new(BIO_s_mem());
    if (!mem_bio) {
        fprintf(stderr, "Error creating memory BIO.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // 5. Chain the BIOs: md_bio -> mem_bio
    chain_bio = BIO_push(md_bio, mem_bio);
    if (!chain_bio) {
        fprintf(stderr, "Error pushing BIOs.\n");
        ERR_print_errors_fp(stderr);
        // Note: BIO_push transfers ownership of mem_bio to md_bio if successful.
        // If it fails, we need to free both individually.
        goto cleanup;
    }

    // 6. Write the data through the BIO chain
    int bytes_written = BIO_write(chain_bio, message, strlen(message));
    if (bytes_written <= 0) {
        fprintf(stderr, "Error writing data to BIO chain.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }
    if (BIO_flush(chain_bio) <= 0) {
         fprintf(stderr, "Error flushing BIO chain.\n");
         ERR_print_errors_fp(stderr);
         goto cleanup;
    }

    // 7. Retrieve the hash digest
    BIO_get_md_ctx(md_bio, &md_ctx);
    if (!md_ctx) {
        fprintf(stderr, "Error getting MD context from BIO.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (!EVP_DigestFinal_ex(md_ctx, hash_digest, &digest_len)) {
        fprintf(stderr, "Error finalizing digest.\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // 8. Print the resulting hash digest
    printf("Original message: %s\n", message);
    printf("SHA-256 Digest: ");
    print_hex(hash_digest, digest_len);

cleanup:
    // 9. Cleanup: Free the BIO chain.
    if (chain_bio) {
        BIO_free_all(chain_bio);
    }
     else {
        if (md_bio) BIO_free(md_bio);
        if (mem_bio) BIO_free(mem_bio);
    }

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

