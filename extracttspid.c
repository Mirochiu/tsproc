#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 4096*188
#define TS_SYNC_BYTE 0x47
#define PID_LIST_SIZE 64

typedef unsigned int pid_t;

int main(int argc, char* argv[])
{
    FILE *infile, *outfile;
    pid_t pid, extractpid;
    int readlen, writelen, procbyte, extractbyte, extractcnt;
    char outfname[128] = {0};
    unsigned char Buf[BUF_SIZE];
    unsigned char *h, *e;

    if (argc <= 2) {
        fprintf(stderr, "Usage: %s <ts-file> <pid> [<out-file>]\n", argv[0]);
        return -1;
    }

    printf("input file: %s\n", argv[1]);
    infile = fopen(argv[1], "rb");
    if (!infile) {
        perror(argv[0]);
        return -1;
    }
    
    extractpid = atoi(argv[2]) & 0x1FFF;
    printf("extract pid: %d\n", extractpid);

    if (argc > 3) {
        strncpy(outfname, argv[3], sizeof(outfname)-1);
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
        snprintf(outfname, sizeof(outfname)-1, "%.*s-%d%s", dot-argv[1], argv[1], extractpid, dot);
    }
    printf("output file: %s\n", outfname);
    outfile = fopen(outfname, "wb");
    if (!outfile) {
        perror(argv[0]);
        return -1;
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
            pid = (((*++h)<<8)|*(++h)) & 0x1FFF;
            if (pid == extractpid) {
                writelen = fwrite(h, 1, 188, outfile);
                if (188 != writelen) {
                    perror(argv[0]);
                    fprintf(stderr, "wrtie error %d != 188\n", writelen);
                    readlen = 0;
                    break;
                }
                extractbyte += 188;
                ++extractcnt;
                if (extractcnt%1000) {
                    fflush(outfile);
                }
            }
            h += 186;
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
    printf("Processed bytes : %d\n", procbyte);
    printf("Extracted bytes : %d\n", extractbyte);
    printf("Extrac/Proc percantage : %.3lf%%\n", extractbyte/(double)procbyte*100.0);
    printf("Extracted TS packet : %d\n", extractcnt);
    
    puts("\nflushing .... please wait minutes");
    fflush(outfile);
    fclose(outfile);
    puts("finish");

    return 0;
}
