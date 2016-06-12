#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE     4096*188
#define TS_SYNC_BYTE 0x47
#define TS_HDR_LEN   4
#define TS_PID_PAT   0x00
#define TS_PAT_TBLID 0x00
#define NOT_FOUND    -1
#define MAX_PMT_NUM 20

#define GET_TS_PID(pPkt)        ((((pPkt)[1]<<8)|(pPkt)[2])&0x1fff)
#define GET_TS_START_INDI(pPkt) (((pPkt)[1]>>6)&0x1)
#define GET_TS_AFC(pPkt)        (((pPkt)[3]&0x30)>>4)
#define GET_TS_ADP_LEN(pPkt)    ((pPkt)[4])
#define GET_12BITS(pData)       ((((pData)[0]&0x0F)<<8)|(pData)[1])
#define GET_13BITS(pData)       ((((pData)[0]&0x1F)<<8)|(pData)[1])
#define GET_16BITS(pData)       (((pData)[0]<<8)|(pData)[1])

typedef unsigned int pid_t;

int main(int argc, char* argv[])
{
    FILE *infile;
    int readlen, idx, ret, procbyte, tbllen;
    int firstpat, lastfound, tscnt, patcnt, firstpmt, firstbpmt, payloadoffset;
    unsigned char Buf[BUF_SIZE];
    unsigned char *h, *e;
    pid_t pid;
    pid_t PmtPid[MAX_PMT_NUM] = {0};
    int PmtNum = 0;

    if (argc <= 1) {
        fprintf(stderr, "Usage: %s <ts-file>\n", argv[0]);
        return -1;
    }

    printf("input file: %s\n", argv[1]);
    infile = fopen(argv[1], "rb");
    if (!infile) {
        perror(argv[0]);
        return -1;
    }

    // find first pat
    firstpat = NOT_FOUND;
    readlen = fread(Buf, 1, BUF_SIZE, infile);
    while (readlen > 0) {
        if (readlen%188 != 0) {
            fprintf(stderr, "read error %d != 188*N, discard %d\n", readlen, readlen%188);
            readlen -= readlen%188;
        }
        h = Buf;
        e = h + readlen;
        while (h != e) {
            if (TS_SYNC_BYTE != *h) {
                fprintf(stderr, "Invalid ts sync byte %d != 188\n", (int)*h);
                readlen = 0;
                break;
            }
            pid = GET_TS_PID(h);
            if (TS_PID_PAT == pid) {
                firstpat = procbyte + (h-Buf); // current byte
                if (!GET_TS_START_INDI(h)) {
                    printf("Found PAT, but the start indicator is false @ %d. Find next PAT\n", firstpat);
                    firstpat = NOT_FOUND;
                    continue;
                }
                payloadoffset = TS_HDR_LEN + ((GET_TS_AFC(h)>=2) ? (GET_TS_ADP_LEN(h)+1) : 0);
                payloadoffset += h[payloadoffset] + 1;
                if (TS_PAT_TBLID != h[payloadoffset]) {
                    fprintf(stderr, "Invalid PAT table ID 0x%02X != 0x00. Find next PAT\n", (int)h[payloadoffset]);
                    firstpat = NOT_FOUND;
                    continue;
                }
                printf("Found PAT @ %d\n", firstpat);
                tbllen = GET_12BITS(h+payloadoffset+1) - 1;
                for (idx=8 ; idx < tbllen ; idx+=4) {
                    printf("idx=%d tblen %d\n", idx, tbllen);
                    if (GET_16BITS(h+payloadoffset+idx)) {
                        if (PmtNum < MAX_PMT_NUM) {
                            PmtPid[PmtNum++] = GET_13BITS(h+payloadoffset+idx+2);
                        } else {
                            fprintf(stderr, "Too many PMT pids in PAT\n");
                        }
                    }
                }
                readlen = 0; // stop the outer loop
                break;
            }
            h += 188;
        }
        if (readlen > 0) {
            tscnt += readlen/188;
            procbyte += readlen;
            if (procbyte%1000) {
                printf(".");
            }
            readlen = fread(Buf, 1, BUF_SIZE, infile);
        }
    }
    if (readlen < 0) {
        perror(argv[0]);
    }
    if (NOT_FOUND == firstpat) {
        fputs("Cannot found the first pat in the specified file\n", stderr);
        return -1;
    }    
    fclose(infile);

    puts  ("\n========= [ Informations ] =========");
    printf("First PAT @ %d byte, %d ts-pkt\n", firstpat, firstpat/188);
    printf("Found %d Pids of PMT in the first PAT\n", PmtNum);
    for (idx=0 ; idx<PmtNum ; ++idx)
        printf("  PMT %2d pid %4d 0x%-04X\n", idx+1, PmtPid[idx], PmtPid[idx]);

    return 0;
}
