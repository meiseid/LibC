/*
hostapライブラリを使用したAES暗号化テスト

git clone git://w1.fi/srv/git/hostap.git
cd hostap/src
make

リンクライブラリはhostap/src/{crypto/libcrypto.a,utils/libutils.a}
およびOpenSSLの -lssl -lcrypto

テストMAINビルド(親ディレクトリにhostapがある場合)
gcc -D_LIB_AES_MAIN -I.. aes.c ../hostap/src/crypto/libcrypto.a
../hostap/src/utils/libutils.a -lssl -lcrypto
*/
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* hostap include */
#ifdef __cplusplus
extern "C" {
#endif
#include "hostap/src/utils/includes.h"
#include "hostap/src/utils/common.h"
#include "hostap/src/crypto/sha1.h"
#include "hostap/src/crypto/crypto.h"
#include "hostap/src/crypto/aes_wrap.h"
#ifdef __cplusplus
} /* extern "C" */
#endif

/* 16進文字列をバイト配列に変換 */
extern unsigned char *lib_hexstr2bin(const char *str, unsigned char *bin) {
  int i, n;
  unsigned int x;
  n = strlen(str);
  if (!bin)
    bin = (unsigned char *)malloc(n);
  for (i = 0; i < n; i += 2) {
    sscanf((char *)(str + i), "%02X", &x);
    bin[i / 2] = x;
  }
  return bin;
}

/* バイト配列を16進文字列に変換 */
extern char *lib_bin2hexstr(const unsigned char *bin, size_t n, char *str) {
  int i, j;
  if (!str)
    str = (char *)malloc(n * 2 + 1);
  for (i = 0, j = 0; i < n; i++, j += 2) {
    sprintf(str + j, "%02X", bin[i]);
  }
  return str;
}

#ifdef _LIB_AES_MAIN
extern int main(int argc, char **argv) {
  /* 共有鍵を取得した所からスタート */
  /* 共有鍵の取得まではdh.cのmainを参照 */
  const char *share_key_str =
      "F538EAF42B189A2EDA578897D35B217F25336CAE68658792B4385CB8FC9FB072C3895C7F"
      "1778AFC3F43BA40C2A9C26B577344742C8E47C76A79500E6EBDC1AE67346DD29DCE11DD9"
      "68802DB0429B1CF8DD74F2A65C332BD8DEF0F0E3071F8AFC8D76C8E4FA6C01DD9C8493AF"
      "AAAA8E5CC6B50052CD23F07DF672B3AB446CA4C87440F29D2780DF272F23203E31FB782B"
      "8FE149628D9BA3FD95E1489CEAA6AA29176E8DAD551425661AA04D539317B8D6968AD5EC"
      "DA8AB01D701F063FE7B4AD90";
  unsigned char *share_key_bin;
  unsigned char prf_k[64], prf_a[64], prf_b[128], prf_data[24];
  unsigned char aes_key[16], aes_nonce[16], aes_data[16];
  u_int64_t packet_counter;
  char buf[512];

  /* 共有鍵文字列をバイナリに戻す */
  share_key_bin = lib_hexstr2bin(share_key_str, NULL);
  lib_bin2hexstr(share_key_bin, 192, buf);
  fprintf(stdout, "Diffie-Hellman SHARED KEY: %s\n", buf);

  /* 1536ビット共有鍵をhostap/prf-192関数で192ビットデータに変換 */
  memcpy(prf_k, share_key_bin, 64);       /* K: 共有鍵上位64バイト */
  strcpy(prf_a, "MEISEI");                /* A: 固定値 今回は MEISEI */
  memcpy(prf_b, share_key_bin + 64, 128); /* B: 共有鍵下位128バイト */
  memset(prf_data, 0, sizeof(prf_data));
  if (sha1_prf(prf_k, 64, prf_a, prf_b, 128, prf_data, 24) != 0) {
    fprintf(stderr, "sha1_prf() error.\n");
    return (-1); /* 変換失敗 */
  }
  lib_bin2hexstr(prf_data, 24, buf);
  fprintf(stdout, "SHA1-PRF-192 OUTPUT: %s\n", buf);

  /* 得られた192ビットの上位128ビットをaes_key、
  下位64ビットをaes_nonceの上位64ビットとする */
  memcpy(aes_key, prf_data, 16);
  memcpy(aes_nonce, prf_data + 16, 8);

  /* あとは送信側がaes_nonceの下位64ビットにパケット番号(カウンタ)、
  aes_dataに好きなデータを入れて暗号化して送る */
  packet_counter = 12345;                    /* とりあえず12345番 */
  memcpy(aes_nonce + 8, &packet_counter, 8); /* セット aes_nonce完成 */
  strcpy(aes_data,
         "あいうえお"); /* UTF-8では3バイト×5+ヌル文字\0でちょうど16バイト */

  /* なおパケット先頭でpacker_counterを送っておかないと、受信側はaes_nonceを完成できないので注意
   */

  /* ダンプ */
  fprintf(stdout, "暗号化前のデータ---------------\n");
  lib_bin2hexstr(aes_key, 16, buf);
  fprintf(stdout, "AES KEY: %s\n", buf);
  lib_bin2hexstr(aes_nonce, 16, buf);
  fprintf(stdout, "AES NONCE: %s\n", buf);
  lib_bin2hexstr(aes_data, 16, buf);
  fprintf(stdout, "AES DATA: %s\n", buf);
  fprintf(stdout, "AES DATA(STR): %s\n", aes_data);

  /* aes128_ctr暗号化 */
  if (aes_128_ctr_encrypt(aes_key, aes_nonce, aes_data, 16) != 0) {
    fprintf(stderr, "sender aes_128_ctr_encrypt() error.\n");
    return (-1); /* 暗号化失敗 */
  }

  /* ダンプ */
  fprintf(stdout, "暗号化したデータ---------------\n");
  lib_bin2hexstr(aes_key, 16, buf);
  fprintf(stdout, "AES KEY: %s\n", buf);
  lib_bin2hexstr(aes_nonce, 16, buf);
  fprintf(stdout, "AES NONCE: %s\n", buf);
  lib_bin2hexstr(aes_data, 16, buf);
  fprintf(stdout, "AES DATA: %s\n", buf);

  /* データを受信したと仮定して、復号化する */
  /* packet_counterをパケット先頭で受信して、受信側もaes_nonceを正しく完成させたものとする
   */

  /* aes128_ctr復号化 */
  if (aes_128_ctr_encrypt(aes_key, aes_nonce, aes_data, 16) != 0) {
    fprintf(stderr, "receiver aes_128_ctr_encrypt() error.\n");
    return (-1); /* 復号化失敗 */
  }

  /* ダンプ */
  fprintf(stdout, "復号化したデータ---------------\n");

  memcpy(&packet_counter, aes_nonce + 8, 8);
  fprintf(stdout, "PACKET_COUNTER: %lld\n", packet_counter);

  lib_bin2hexstr(aes_key, 16, buf);
  fprintf(stdout, "AES KEY: %s\n", buf);
  lib_bin2hexstr(aes_nonce, 16, buf);
  fprintf(stdout, "AES NONCE: %s\n", buf);
  lib_bin2hexstr(aes_data, 16, buf);
  fprintf(stdout, "AES DATA: %s\n", buf);
  fprintf(stdout, "AES DATA(STR): %s\n", aes_data);

  return 0;
}
#endif /* _LIB_AES_MAIN */
