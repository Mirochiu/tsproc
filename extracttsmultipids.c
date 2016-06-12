#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 4096*188
#define TS_SYNC_BYTE 0x47
#define GET_TS_PID(pPkt)        ((((pPkt)[1]<<8)|(pPkt)[2])&0x1fff)

typedef unsigned int pid_t;

int main(int argc, char* argv[])
{
    FILE *infile, *outfile;
    pid_t pid;
    int readlen, writelen, procbyte, extractbyte, extractcnt, idx;
    char outfname[128] = {0};
    unsigned char Buf[BUF_SIZE];
    unsigned char *h, *e;
    pid_t* ExtPid = 0;
    int PidNum = 0;

    if (argc <= 3) {
        fprintf(stderr, "Usage: %s <ts-file> <out-file> <pid> [<2nd-pid> [<3rd-pid> [...]]\n", argv[0]);
        fprintf(stderr, "  <out-file> : if set '-', we will generate the output file name automatically\n");
        return -1;
    }

    printf("input file: %s\n", argv[1]);
    infile = fopen(argv[1], "rb");
    if (!infile) {
        perror(argv[0]);
        return -1;
    }

    if (argv[2][1] != '-') {
        strncpy(outfname, argv[2], sizeof(outfname)-1);
    }
    else {
#if defined(_WIN32)
        char* slash = strrchr(argv[1], '\\');
#else
        char* slash = strrchr(argv[1], '/');
#endif
        char* dot = strrchr(argv[1], '.');
        if (dot < slash) {
            dot = 0;
        }
        if (!dot) {
            dot = argv[1] + strlen(argv[1]);
            printf("dot=%p '%c'\n", dot, *dot);
        }
        snprintf(outfname, sizeof(outfname)-1, "%.*s-multipids%s", dot-argv[1], argv[1], dot);
    }
    printf("output file: %s\n", outfname);
    outfile = fopen(outfname, "wb");
    if (!outfile) {
        perror(argv[0]);
        return -1;
    }
    
    PidNum = argc-3;
    ExtPid = malloc(sizeof(pid_t)*PidNum);
    if (!ExtPid) {
        perror(argv[0]);
        fputs("cannot allocate more memory for pid list", stderr);
        return -1;
    }
    printf("Extract %d Pid List:\n", PidNum);
    for (idx=0 ; idx<PidNum ; ++idx) {
        ExtPid[idx] = atoi(argv[3+idx]) & 0x1FFF;
        printf(" Pid %2d : %04d 0x%-04X\n", idx+1, ExtPid[idx], ExtPid[idx]);
    }

    procbyte = 0;
    extractbyte = 0;
    extractcnt = 0;
    readlen = fread(Buf, 1, BUF_SIZE, infile);
    while (readlen > 0) {
        if (readlen%188 != 0) {
            fprintf(stderr, "read error %d != 188*N\n", readlen);
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
            for(idx=0 ; idx<PidNum && pid!=ExtPid[idx]; ++idx)
                ; // empty
            if (idx != PidNum) {
                writelen = fwrite(h, 1, 188, outfile);
                if (188 != writelen) {
                    perror(argv[0]);
                    fprintf(stderr, "wrtie error %d != 188\n", writelen);
                    readlen = 0;
                    break;
                }
                extractbyte += 188;
                ++extractcnt;
            }
            h += 188;
        }
        if (readlen > 0) {
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
    printf("Selected %d Pids\n", PidNum);
    for (idx=0 ; idx<PidNum ; ++idx) {
        printf("  Pid %d : %4d 0x%-04X\n", idx+1, ExtPid[idx], ExtPid[idx]);
    }
    printf("Processed bytes : %d\n", procbyte);
    printf("Extracted bytes : %d\n", extractbyte);
    printf("Extrac/Proc percantage : %.3lf%%\n", extractbyte/(double)procbyte*100.0);
    printf("Extracted TS packet : %d\n", extractcnt);
    
    puts("\nflushing .... please wait minutes");
    fflush(outfile);
    fclose(outfile);
    puts("finish");

    free(ExtPid);
    
    return 0;
}
