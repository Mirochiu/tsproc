#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 4096*188
#define TS_SYNC_BYTE 0x47
#define NOT_FOUND_SYNC (-1)

typedef unsigned int pid_t;

int main(int argc, char* argv[])
{
    FILE *infile, *outfile;
    pid_t pid, extractpid;
    int idx, readlen, writelen, procbyte, extractbyte, firstsync;
    char outfname[128] = {0};
    unsigned char Buf[BUF_SIZE];
    unsigned char *h, *e;

    if (argc <= 1) {
        fprintf(stderr, "Usage: %s <ts-file> [<out-file>]\n", argv[0]);
        return -1;
    }

    printf("input file: %s\n", argv[1]);
    infile = fopen(argv[1], "rb");
    if (!infile) {
        perror(argv[0]);
        return -1;
    }

    // find sync byte
    readlen = fread(Buf, 1, BUF_SIZE, infile);
    if (readlen < 0) {
        fprintf(stderr, "cannot read data from file, %d\n", readlen);
        perror(argv[0]);
        return -1;
    }
    readlen -= readlen%188;
    if (0 == readlen) {
        fprintf(stderr, "specified file too small, cannot find the alignment\n");
        return -1;
    }

    firstsync = NOT_FOUND_SYNC;
    for (idx=0 ; idx<188 ; ++idx) {
        h = Buf + idx;
        e = h + readlen;
        while (h < e && TS_SYNC_BYTE == *h) {
            h += 188;
        }
        if (h == e) {
            firstsync = idx;
            break;
        }
    }
    if (NOT_FOUND_SYNC == firstsync) {
        fprintf(stderr, "cannot find valid ts alignement.\n"
            " Are you sure the file is the MPEG-TS format?\n", readlen);
        return -1;
    }
    if (!firstsync) {
        puts("The sync byte of specified file is okay, cancel the alignement");
        return 0;
    }
    printf("fist sync byte @ %d\n", firstsync);

    // open output file
    if (argc > 2) {
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
        snprintf(outfname, sizeof(outfname)-1, "%.*s-aligned%s", dot-argv[1], argv[1], dot);
    }
    printf("output file: %s\n", outfname);
    outfile = fopen(outfname, "wb");
    if (!outfile) {
        perror(argv[0]);
        return -1;
    }

    // write out the ts packets after the first sync byte.
    procbyte = firstsync;
    extractbyte = 0;
    fseek(infile, firstsync, SEEK_SET);
    readlen = fread(Buf, 1, BUF_SIZE, infile);
    while (readlen > 0) {
        if (readlen%188 != 0) {
            fprintf(stderr, "read error %d != 188*N, discard %d bytes\n", readlen, readlen%188);
            readlen -= readlen%188;
        }
        writelen = fwrite(Buf, 1, readlen, outfile);
        if (readlen != writelen) {
            perror(argv[0]);
            fprintf(stderr, "wrtie error:  %d != %d\n", writelen, readlen);
            readlen = 0;
            break;
        }
        extractbyte += writelen;
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
    printf("First sync byte @ %d\n", firstsync);
    printf("Processed bytes : %d\n", procbyte);
    printf("Extracted bytes : %d\n", extractbyte);

    puts("\nflushing .... please wait minutes");
    fflush(outfile);
    fclose(outfile);
    puts("finish");

    return 0;
}
