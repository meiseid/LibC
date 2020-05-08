/*
Diffie-Hellman法による秘密鍵、公開鍵、共有鍵の計算テスト
1536ビットMODPグループの固定素数p/自然数gを使用
https://www.ipa.go.jp/security/rfc/RFC3526JA.html
https://wiki.openssl.org/index.php/Diffie-Hellman_parameters
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OpenSSL version 1.1以上専用 1.0以下はコンパイル不可
 1.1以上はdh構造体への直接アクセスは不可で、set,get関数を介す
 詳しくはopenssl/dh.hを参照
*/
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

/* Diffie-Hellman秘密鍵と公開鍵を自動生成 */
extern DH *lib_dh1536generate(const char *rnd_seed) {
  /* 素数p (prime) */
  static unsigned char dh1536_p[] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
      0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
      0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
      0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
      0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
      0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
      0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
      0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
      0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
      0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
      0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
      0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
      0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
      0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
      0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
      0xCA, 0x23, 0x73, 0x27, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  /* 生成元g (generator) */
  static unsigned char dh1536_g[] = {0x02};
  DH *dh;
  const BIGNUM *p, *g;

  int ck, flags = 0;
  long residue;

  if ((dh = DH_new()) == NULL)
    return (NULL); /* 初期化 */

  /* prime, generatorセット */
  DH_set0_pqg(dh, BN_bin2bn(dh1536_p, sizeof(dh1536_p), NULL), NULL,
              BN_bin2bn(dh1536_g, sizeof(dh1536_g), NULL));

  DH_get0_pqg(dh, &p, NULL, &g);
  if (!p || !g) {
    DH_free(dh);
    return NULL;
  }

  RAND_seed(rnd_seed, strlen(rnd_seed));

  if (!DH_check(dh, &ck)) {
    DH_free(dh);
    return NULL;
  }

  if (BN_is_word(g, DH_GENERATOR_2)) {
    residue = BN_mod_word(p, 24);
    if (residue == 11 || residue == 23) {
      ck &= ~DH_NOT_SUITABLE_GENERATOR;
    }
  }

  if (ck & DH_CHECK_P_NOT_PRIME) {
    fprintf(stderr, "DH_CHECK_P_NOT_PRIME\n");
  }
  if (ck & DH_CHECK_P_NOT_SAFE_PRIME) {
    fprintf(stderr, "DH_CHECK_P_NOT_SAFE_PRIME\n");
  }
  if (ck & DH_UNABLE_TO_CHECK_GENERATOR) {
    fprintf(stderr, "DH_UNABLE_TO_CHECK_GENERATOR\n");
  }
  if (ck & DH_NOT_SUITABLE_GENERATOR) {
    fprintf(stderr, "DH_NOT_SUITABLE_GENERATOR\n");
  }

  flags &= ~DH_FLAG_NO_EXP_CONSTTIME;
  DH_set_flags(dh, flags);

  if (!DH_generate_key(dh)) {
    DH_free(dh);
    return NULL;
  }

  /* DHparams_print_fp(stderr, dh); */

  return (dh);
}

/* Diffie-Hellman秘密鍵と公開鍵から共有鍵を生成 */
extern unsigned char *lib_dh1536compute(DH *dh, unsigned char *inpub,
                                        unsigned char *outcom) {
  BIGNUM *bn;
  int len;

  if (!dh || !inpub || !outcom)
    return NULL;

  if ((bn = BN_bin2bn(inpub, 192, NULL)) == NULL)
    return NULL;

  len = DH_compute_key(outcom, bn, dh);

  BN_free(bn);

  if (len == 192)
    return outcom; /* 192バイトなら成功 */

  fprintf(stderr, "DH_compute_key_NOT_192_BYTES\n");
  return NULL;
}

/* TEST MAIN
gcc -D_LIB_DH_MAIN dh.c -lssl -lcrypto
*/
#ifdef _LIB_DH_MAIN
extern int main(int argc, char **argv) {
  char *ptr;
  int i, len;
  DH *dh_X, *dh_Y;
  const BIGNUM *priv_key_X, *priv_key_Y;
  const BIGNUM *pub_key_X, *pub_key_Y;
  unsigned char pub_key_bin_X[192], pub_key_bin_Y[192];
  unsigned char share_key_bin_X[192], share_key_bin_Y[192];
  char share_key_str_X[512], share_key_str_Y[512];

  /* システムＸ、Ｙそれぞれ秘密鍵・公開鍵生成 */

  dh_X = lib_dh1536generate("I have a pen, I have a apple.");
  if (!dh_X) {
    return (-1);
  }
  dh_Y = lib_dh1536generate("Ah, pen pine apple apple pen.");
  if (!dh_Y) {
    DH_free(dh_X);
    return (-1);
  }

  DH_get0_key(dh_X, &pub_key_X, &priv_key_X);
  DH_get0_key(dh_Y, &pub_key_Y, &priv_key_Y);

  /* 公開鍵の長さチェック */

  if (BN_num_bytes(pub_key_X) != 192 || BN_num_bytes(pub_key_Y) != 192) {
    fprintf(stderr, "公開鍵が192バイトではありません\n");
    DH_free(dh_X);
    DH_free(dh_Y);
    return (-1);
  }

  /* 秘密鍵・公開鍵情報ダンプ */

  if ((ptr = BN_bn2hex(priv_key_X)) != NULL) {
    fprintf(stdout, "システムＸの秘密鍵a:\n%s\n", ptr);
    OPENSSL_free(ptr);
  }
  if ((ptr = BN_bn2hex(pub_key_X)) != NULL) {
    fprintf(stdout, "システムＸの公開鍵Ａ:\n%s\n", ptr);
    OPENSSL_free(ptr);
  }

  if ((ptr = BN_bn2hex(priv_key_Y)) != NULL) {
    fprintf(stdout, "システムＹの秘密鍵b:\n%s\n", ptr);
    OPENSSL_free(ptr);
  }
  if ((ptr = BN_bn2hex(pub_key_Y)) != NULL) {
    fprintf(stdout, "システムＹの公開鍵Ｂ:\n%s\n", ptr);
    OPENSSL_free(ptr);
  }

  /* 公開鍵をバイナリデータに変換 */

  BN_bn2bin(pub_key_X, pub_key_bin_X);
  BN_bn2bin(pub_key_Y, pub_key_bin_Y);

  /* 鍵交換 = 自分の秘密鍵と相手の公開鍵から共有鍵Ｋを生成 */

  if (!lib_dh1536compute(dh_X, pub_key_bin_Y, share_key_bin_X) ||
      !lib_dh1536compute(dh_Y, pub_key_bin_X, share_key_bin_Y)) {
    DH_free(dh_X);
    DH_free(dh_Y);
    return (-1);
  }

  /* ダンプ用に文字列化 */

  for (i = 0, len = 0; i < 192; i++) {
    len += sprintf(share_key_str_X + len, "%02X", share_key_bin_X[i]);
  }

  for (i = 0, len = 0; i < 192; i++) {
    len += sprintf(share_key_str_Y + len, "%02X", share_key_bin_Y[i]);
  }

  /* ２つの共有鍵は同じになるはずである */

  fprintf(stdout, "システムＸの共有鍵Ｋ:\n%s\n", share_key_str_X);
  fprintf(stdout, "システムＹの共有鍵Ｋ:\n%s\n", share_key_str_Y);

  DH_free(dh_X);
  DH_free(dh_Y);

  return 0;
}
#endif /* _LIB_DH_MAIN */
