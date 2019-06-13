#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

void printAesKey(AES_KEY* key, unsigned char* keyname) {
    int idx;
    unsigned char* ptr;
    printf("======== < %10s > =======\n", keyname);
    printf("Rounds: %d\n", key->rounds);
    printf("Key length: %lu\n", sizeof(key->rd_key));
    ptr = (unsigned char*) (key->rd_key);
    for (idx=0 ; idx<sizeof(key->rd_key); ++idx) {
        printf("%02X", (int)*ptr++);
    }
    printf("\n");
}

#define BUF_SIZE 188*1000
#define KEY_BITS 128

#define CLR_TS_SCRAM_CTRL(pPkt)        ((pPkt)[3]&=(~0xC0))

#define TS_PACKET_SIZE  188
#define TS_SYNC_BYTE    0x47
#define TS_HDR_LEN      4
#define PID_NULL_PKT    0x1fff
#define PID_PAT         0x00
#define GET_TS_PID(pPkt)        ((((pPkt)[1]<<8)|(pPkt)[2])&0x1fff)
#define GET_TS_START_INDI(pPkt) (((pPkt)[1]>>6)&0x1)
#define GET_TS_SCRAM_CTRL(pPkt) (((pPkt)[3]&0xC0)>>6)
#define GET_TS_AFC(pPkt)        (((pPkt)[3]&0x30)>>4)
#define GET_TS_ADP_LEN(pPkt)    ((pPkt)[4])
#define GET_12BITS(pData)       ((((pData)[0]&0x0F)<<8)|(pData)[1])
#define GET_13BITS(pData)       ((((pData)[0]&0x1F)<<8)|(pData)[1])
#define GET_16BITS(pData)       (((pData)[0]<<8)|(pData)[1])
#define GET_USHORT              GET_16BITS
#define GET_PID                 GET_13BITS
#define PSI_HDR_LEN 1
#define SECTION_HDR_LEN 3
#define PAT_HDR_LEN 8
#define PAT_TAIL_LEN 4
#define PAT_PROG_LEN 4
#define PMT_HDR_LEN 12
#define PMT_TAIL_LEN 4
#define PMT_PROG_INFO_LEN 2
#define TABLE_ID_PAT 0x00
#define TABLE_ID_PMT 0x02

#define PMT_VIDEO_STREAM_DESCRIPTOR         0x02
#define PMT_AUDIO_STREAM_DESCRIPTOR         0x03
#define PMT_CA_DESCRIPTOR                   0x09
#define PMT_LANGUAGE_DESCRIPTOR             0x0A
#define PMT_SUBTITLING_DESCRIPTOR           0x59

#define PMT_STREAM_TYPE_11172_VIDEO         0x01
#define PMT_STREAM_TYPE_13818_VIDEO         0x02
#define PMT_STREAM_TYPE_11172_AUDIO         0x03
#define PMT_STREAM_TYPE_13818_AUDIO         0x04
#define PMT_STREAM_TYPE_ADTS                0x0F
#define PMT_STREAM_TYPE_14496_2_MPEG4       0x10
#define PMT_STREAM_TYPE_14496_3_AAC         0x11
#define PMT_STREAM_TYPE_AVC_H264            0x1B
#define PMT_STREAM_TYPE_HEVC_H265           0x24
#define PMT_STREAM_TYPE_AVS                 0x42
#define PMT_STREAM_TYPE_AC3                 0x81
#define PMT_STREAM_TYPE_DTS                 0x82
#define PMT_STREAM_TYPE_DOLBY_TRUEHD        0x83
#define PMT_STREAM_TYPE_PRIVATE             0x06

#define PMT_STREAM_LANGUAGE_DESCRIPTOR      PMT_LANGUAGE_DESCRIPTOR
#define PMT_STREAM_MPEG2_AAC_DESCRIPTOR     0x2b
#define PMT_STREAM_AC3_DESCRIPTOR           0x6a

#define DESCRAMBLE_SUCCEED 0

AES_KEY cryptkey;

unsigned char inkey[KEY_BITS/8] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff    
};
unsigned char initvec[KEY_BITS/8] = {
    0x44, 0x56, 0x42, 0x54,
    0x4d, 0x43, 0x50, 0x54,
    0x41, 0x45, 0x53, 0x43,
    0x49, 0x53, 0x53, 0x41
};

typedef int (*decryptOneTs_t) (unsigned char*, unsigned char*, int);

static decryptOneTs_t descrambler;

int decryptTsPayloadMod(unsigned char* tspkt, unsigned char* dec_pkt, int scrm_ctl) {
    if (!scrm_ctl) return DESCRAMBLE_SUCCEED;
    int payloadOffset = TS_HDR_LEN + ((GET_TS_AFC(tspkt)>=2) ? (GET_TS_ADP_LEN(tspkt)+1) : 0);
    if (payloadOffset>=0 && payloadOffset<=TS_PACKET_SIZE) {
        int remaining_size = TS_PACKET_SIZE-payloadOffset;
        int enc_size = remaining_size - (remaining_size%(KEY_BITS/8));
        memcpy(dec_pkt, tspkt, TS_PACKET_SIZE);
        CLR_TS_SCRAM_CTRL(dec_pkt);
        if (enc_size>0) {
            AES_cbc_encrypt(tspkt+payloadOffset, dec_pkt+payloadOffset, enc_size, &cryptkey, initvec, AES_DECRYPT);
        }
    } else {
        fprintf(stderr, "error payload offset %d\n",payloadOffset);
        return !DESCRAMBLE_SUCCEED;
    }
    return DESCRAMBLE_SUCCEED;
}

void dump_one_ts(unsigned char* buf, char* title) {
    unsigned char* ptr = buf;
    unsigned char* end = buf + 188;
    printf("====[%s]====\n",title);
    while (ptr != end) {
        printf("%02x ", (int)*ptr++);
        if (!((ptr-buf)&0xf)) printf("\n");
    }
    printf("\n============\n");
}

int readTsDataFromHexString(unsigned char* buf, int buf_size, unsigned char* string) {
    unsigned int val;
    unsigned char* ptr = buf;
    unsigned char* end = buf + buf_size;
    FILE* f;
    f = fmemopen(string, strlen(string), "r");
    if (!f) {
        perror("fmemopen");
        return 0;
    }
    //printf("====\n");
    while (ptr != end && fscanf(f, "%x", &val)>0) {
        *ptr = val;
        //printf("%02x ", (int)*ptr);
        //if (!((ptr-buf)&0xf)) printf("\n");
        ptr++;
    }
    //printf("\n====\n");
    fclose(f);
    return ptr-buf;
}

int descramble_one_ts(unsigned char* scrambled_buf, unsigned char* descrambled_buf) {
    int scrm_ctl;
    int ret = DESCRAMBLE_SUCCEED;
    if (TS_SYNC_BYTE != scrambled_buf[0]) {
        fprintf(stderr, "invalid ts sync byte\n");
        return ret;
    }
    if (PID_NULL_PKT == GET_TS_PID(scrambled_buf)) {
        return ret;
    }
    scrm_ctl = GET_TS_SCRAM_CTRL(scrambled_buf);
    if (scrm_ctl) {
        ret = descrambler(scrambled_buf, descrambled_buf, scrm_ctl);
        if (DESCRAMBLE_SUCCEED != ret) {
            fprintf(stderr, "descrambler error %d\n", ret);
            return ret;
        }
    } else {
        memcpy(descrambled_buf, scrambled_buf, TS_PACKET_SIZE);
    }
    return ret;
}

int assert_one_ts(unsigned char* buf1, unsigned char* buf2) {
    int idx;
    for (idx = 0 ; idx<TS_PACKET_SIZE ; ++idx) {
        if (buf1[idx] != buf2[idx]) {
            fprintf(stderr, "pos=%d %d!=%d", idx, buf1[idx], buf2[idx]);
            return 0;
        }
    }
    return 1;
}

int main (int argc, char* argv[])
{
    FILE *infile;
    unsigned char scrambled_buf[BUF_SIZE];
    unsigned char clear_buf[BUF_SIZE];
    unsigned char processed_buf[BUF_SIZE];
    int readlen;

    descrambler = decryptTsPayloadMod;

    AES_set_decrypt_key(inkey, KEY_BITS, &cryptkey);
    printAesKey(&cryptkey, "decrypt key");

    readlen = readTsDataFromHexString(clear_buf, BUF_SIZE, 
"47 60 80 31 06 00 FF FF FF FF FF 54 68 69 73 20 \
69 73 20 74 68 65 20 70 61 79 6c 6f 61 64 20 75 \
73 65 64 20 66 6f 72 20 63 72 65 61 74 69 6e 67 \
20 74 68 65 20 74 65 73 74 20 76 65 63 74 6f 72 \
73 20 66 6f 72 20 74 68 65 20 44 56 42 20 49 50 \
54 56 20 73 63 72 61 6d 62 6c 65 72 2f 64 65 73 \
63 72 61 6d 62 6c 65 72 2e 20 54 68 69 73 20 69 \
73 20 74 68 65 20 70 61 79 6c 6f 61 64 20 75 73 \
65 64 20 66 6f 72 20 63 72 65 61 74 69 6e 67 20 \
74 68 65 20 74 65 73 74 20 76 65 63 74 6f 72 73 \
20 66 6f 72 20 74 68 65 20 44 56 42 20 49 50 54 \
56 20 73 63 72 61 6d 62 6c 65 72 2f");
    if (readlen != 188) {
        fprintf(stderr, "read ts length error %d\n", readlen);
        return -1;
    }
    dump_one_ts(clear_buf, "clear buffer");

    readlen = readTsDataFromHexString(scrambled_buf, BUF_SIZE, 
"47 60 80 b1 06 00 FF FF FF FF FF 15 ce 67 e0 cb \
01 b5 3c e7 60 54 e5 7a 4a d1 20 a0 df a4 ea aa \
e9 32 c6 78 3f 51 ae 19 fa ee 10 8b db 78 f3 11 \
3e c2 b5 72 cc 20 85 00 a5 2c ec a1 14 12 6c 58 \
24 4d f5 63 e7 a9 b4 e0 41 cb c3 fb ff fb d8 3c \
8f bf fb 10 e8 3e a3 82 04 ba d7 02 fb 01 a2 7b \
62 2c 4f 85 aa b6 aa 75 55 97 20 d6 5a b8 44 ce \
a2 8c f2 e1 fe 5e 7a c1 9d 44 81 89 19 c2 32 49 \
f1 40 75 7b 5d 16 c0 af 45 b2 5f 50 9b 9d a0 61 \
97 12 c5 9f 0b 39 b0 6f 1f be 90 12 3f 21 29 83 \
93 6a 95 31 7f cb 62 f4 34 6a 1b 1e 16 48 40 30 \
3a ff 83 8a 01 9b f8 10 a8 e0 b2 2f");
    if (readlen != 188) {
        fprintf(stderr, "read ts length error %d\n", readlen);
        return -1;
    }
    dump_one_ts(scrambled_buf, "scrambled buffer");

    descramble_one_ts(scrambled_buf, processed_buf);

    dump_one_ts(processed_buf, "descrambled buffer");

    printf("ASSERT(DESCRAMBLED,CLEAR) => %s\n", (assert_one_ts(processed_buf, clear_buf)?"TRUE":"FALSE"));

    return 0;
}

