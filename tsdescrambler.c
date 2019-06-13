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

// a sample key
unsigned char inkey[KEY_BITS/8] = {
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11        
};
// a sample iv
unsigned char initvec[KEY_BITS/8] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
};
// default initialized vector in ts_103127v010101p.pdf
/*
unsigned char initvec[KEY_BITS/8] = {
    0x44, 0x56, 0x42, 0x54,
    0x4d, 0x43, 0x50, 0x54,
    0x41, 0x45, 0x53, 0x43,
    0x49, 0x53, 0x53, 0x41
};
*/

typedef int (*decryptOneTs_t) (unsigned char*, unsigned char*, int);

static decryptOneTs_t descrambler;
static int last_scrm_ctl;

int decryptTsPayloadMod(unsigned char* tspkt, unsigned char* dec_pkt, int scrm_ctl) {
    if (!scrm_ctl) return DESCRAMBLE_SUCCEED;
    int payloadOffset = TS_HDR_LEN + ((GET_TS_AFC(tspkt)>=2) ? (GET_TS_ADP_LEN(tspkt)+1) : 0);
    if (payloadOffset>=0 && payloadOffset<=TS_PACKET_SIZE) {
        int remaining_size = TS_PACKET_SIZE-payloadOffset;
        int enc_size = remaining_size - (remaining_size%(KEY_BITS/8));
        memcpy(dec_pkt, tspkt, TS_PACKET_SIZE);
        CLR_TS_SCRAM_CTRL(dec_pkt);
        if (enc_size>0) {
            // TODO: change key&iv by scrm_ctl (even/odd)
            AES_cbc_encrypt(tspkt+payloadOffset, dec_pkt+payloadOffset, enc_size, &cryptkey, initvec, AES_DECRYPT);
        }
    } else {
        fprintf(stderr, "error payload offset %d\n",payloadOffset);
        return !DESCRAMBLE_SUCCEED;
    }
    return DESCRAMBLE_SUCCEED;
}

void clearTsScrambleCtrl() {
    last_scrm_ctl = -1;
}

void onTsScrambleCtrl(int scrm_ctl) {
    if (last_scrm_ctl != scrm_ctl) {
        if (last_scrm_ctl == -1) {
            printf("scrm_ctl found %d\n", scrm_ctl);
        } else {
            printf("scrm_ctl changed %d %d\n", last_scrm_ctl, scrm_ctl);
        }
        last_scrm_ctl = scrm_ctl;
    }
}

int descramble_one_ts(unsigned char* scrambled_buf, unsigned char* output_buf) {
    int scrm_ctl;
    int ret = DESCRAMBLE_SUCCEED;
    if (TS_SYNC_BYTE != scrambled_buf[0]) {
        fprintf(stderr, "invalid ts sync byte\n");
        return -1;
    }
    if (PID_NULL_PKT == GET_TS_PID(scrambled_buf)) {
        return ret;
    }
    scrm_ctl = GET_TS_SCRAM_CTRL(scrambled_buf);
    if (scrm_ctl) {
        onTsScrambleCtrl(scrm_ctl);
        ret = descrambler(scrambled_buf, output_buf, scrm_ctl);
        if (DESCRAMBLE_SUCCEED != ret) {
            fprintf(stderr, "descrambler error %d\n", ret);
            return ret;
        }
    } else {
        memcpy(output_buf, scrambled_buf, TS_PACKET_SIZE);
    }
    return ret;
}

void printArray(unsigned char* buf, int size, char* title) {
    unsigned char* ptr = buf;
    unsigned char* end = buf + size;
    if (!buf || size<0) return;
    printf("====[%s]====\n",title);
    while (ptr != end) {
        printf("%02x ", (int)*ptr++);
        if (!((ptr-buf)&0xf)) printf("\n");
    }
    if (size>16) printf("\n");
    printf("============\n");
}

int main (int argc, char* argv[])
{
    FILE *infile, *outfile;
    int dec_cnt = 0, dec_fail_cnt = 0, total_pkt_cnt = 0;
    int i;
    unsigned char outfname[128] = {0};
    unsigned char filebuf[BUF_SIZE];
    unsigned char outbuf[BUF_SIZE];
    int readlen, writelen;

    if (argc <= 1) {
        fprintf(stderr, "usage: %s <in-ts-file> [<out-ts-file=*_dec*>]\n", argv[0]);
        return -1;
    }

    descrambler = decryptTsPayloadMod;
    clearTsScrambleCtrl();

    printArray(inkey,   sizeof(inkey),   "AES128 key");
    printArray(initvec, sizeof(initvec), "Initialization Vector");

    AES_set_decrypt_key(inkey, KEY_BITS, &cryptkey);
    printAesKey(&cryptkey, "Full decrypt key");

    // find the extension name of input file path when parameter not found
    if (argc > 2) {
        strncpy(outfname, argv[2], sizeof(outfname)-1);
    }
    else {
        char *dot, *slash;
        int fname_len = strlen(argv[1]);
        dot = strrchr(argv[1], '.');
        slash = strrchr(argv[1], '/');
        if (dot > slash) {
            fname_len = dot-argv[1];
        }
        snprintf(outfname, sizeof(outfname)-1, "%.*s_dec%s",
            fname_len, argv[1], dot?dot:"");
    }

    outfile = fopen(outfname, "wb");
    if (!outfile) {
        fprintf(stderr, "out file %s error\n", outfname);
        perror(argv[0]);
        return -1;
    }

    // start to process the data
    infile = fopen(argv[1], "rb");
    if (!infile) {
        fprintf(stderr, "input file %s error\n", argv[1]);
        perror(argv[0]);
        return -1;
    }
    printf("input: %s\n", argv[1]);

    while ((readlen = fread(filebuf, 1, BUF_SIZE, infile)) > 0) {
        if (readlen != BUF_SIZE) {
            break;
        }
        for (i=0 ; i+TS_PACKET_SIZE<=readlen ; i+=TS_PACKET_SIZE) {
            ++total_pkt_cnt;
            descramble_one_ts(filebuf+i, outbuf+i);
        }
        writelen = fwrite(outbuf, 1, readlen, outfile);
        if (writelen != readlen) {
            fprintf(stderr, "cannot output the data %d/%d, exit\n", writelen, readlen);
            break;
        }
        printf(".");
    }
    printf("\n");
    if (readlen<0) {
        perror("fread");
    }

    printf("\ndec=%d fail=%d total=%d\n",dec_cnt, dec_fail_cnt, total_pkt_cnt);

    fclose(infile);
    fflush(outfile);
    fclose(outfile);

    return 0;
}

