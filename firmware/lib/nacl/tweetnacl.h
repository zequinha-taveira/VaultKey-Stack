#ifndef TWEETNACL_H
#define TWEETNACL_H

#define crypto_sign_ed25519_tweet_PUBLICKEYBYTES 32
#define crypto_sign_ed25519_tweet_SECRETKEYBYTES 64
#define crypto_sign_ed25519_tweet_BYTES 64

extern int crypto_sign_ed25519_tweet(unsigned char *sm,
                                     unsigned long long *smlen,
                                     const unsigned char *m,
                                     unsigned long long mlen,
                                     const unsigned char *sk);
extern int crypto_sign_ed25519_tweet_open(unsigned char *m,
                                          unsigned long long *mlen,
                                          const unsigned char *sm,
                                          unsigned long long smlen,
                                          const unsigned char *pk);
extern int crypto_sign_ed25519_tweet_keypair(unsigned char *pk,
                                             unsigned char *sk);

extern int crypto_hash_sha512_tweet(unsigned char *out, const unsigned char *m,
                                    unsigned long long n);

#endif
