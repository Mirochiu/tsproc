#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 4096*188
#define TS_SYNC_BYTE 0x47
#define TS_PID_PAT 0x00
#define NO_LAST_FOUND -1

#define GET_TS_PID(pPkt)        ((((pPkt)[1]<<8)|(pPkt)[2])&0x1fff)

typedef unsigned int pid_t;

int main(int argc, char* argv[])
{
    FILE* infile;
    int readlen, idx, ret, procbyte;
    int firstpat, lastfound, tscnt, patcnt;
    long long sumpatdif;
    unsigned char Buf[BUF_SIZE];
    unsigned char *h, *e;
    pid_t pid;

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

    lastfound = NO_LAST_FOUND;
    procbyte = 0;
    tscnt = 0;
    patcnt = 0;
    sumpatdif = 0;
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
                if (NO_LAST_FOUND == lastfound) {
                    firstpat = procbyte + (h-Buf); // current byte
                    printf("Found First PAT @ %d\n", firstpat);
                }
                else {
                    sumpatdif += (procbyte + (h-Buf)) - lastfound;
                }
                lastfound = procbyte + (h-Buf);
                ++patcnt;
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
    fclose(infile);

    puts  ("\n========= [ Statistics ] =========");
    printf("First PAT @ %d byte, %d ts-pkt\n", firstpat, firstpat/188);
    printf("Processed bytes : %d\n", procbyte);
    printf("TS packets : %d\n", tscnt);
    printf("PAT counts : %d\n", patcnt);
    printf("PAT-TS rate : %.3lf%%\n", patcnt/(double)tscnt*100.0);
    printf("Average PAT distance : %.2lf\n", sumpatdif/(double)(patcnt-1));

    return 0;
}
