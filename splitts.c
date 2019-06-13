#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PKT_SIZE 188
#define CAP_PKT_IN_BUF 1000
#define BUF_SIZE (PKT_SIZE*CAP_PKT_IN_BUF)

int main (int argc, char* argv[])
{
    FILE *infile, *outfile;
    unsigned char outfname[128] = {0};
    unsigned char filebuf[BUF_SIZE];
    int readlen, writelen;
    int limit_cnt = 1000, total_cnt = 0;

    if (argc <= 1) {
        fprintf(stderr, "usage: %s <in-file> [<count=1000> [<out-file=*_part*>]]\n", argv[0]);
        return -1;
    }

    if (argc > 2) {
        limit_cnt = atoi(argv[2]);
    }

    // find the extension name of input file path when parameter not found
    if (argc > 3) {
        strncpy(outfname, argv[3], sizeof(outfname)-1);
    } else {
        char *dot, *slash;
        int fname_len = strlen(argv[1]);
        dot = strrchr(argv[1], '.');
        slash = strrchr(argv[1], '/');
        if (dot > slash) {
            fname_len = dot-argv[1];
        }
        snprintf(outfname, sizeof(outfname)-1, "%.*s_part%s",
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

    printf("input  : %s\n", argv[1]);
    printf("count  : %d\n", limit_cnt);
    printf("output : %s\n", outfname);

    readlen = fread(filebuf, 1, PKT_SIZE*CAP_PKT_IN_BUF, infile);
    while (readlen > 0) {
        int read_pkt_cnt = readlen / PKT_SIZE;
        if (total_cnt + read_pkt_cnt > limit_cnt) {
            read_pkt_cnt = limit_cnt-total_cnt;
        }
        if (readlen > 0) {
            writelen = fwrite(filebuf, 1, PKT_SIZE*read_pkt_cnt, outfile);
            if (writelen != PKT_SIZE*read_pkt_cnt) {
                fprintf(stderr, "cannot output the data, request:%d got:%d, exit\n", PKT_SIZE*read_pkt_cnt, writelen);
                break;
            }
        }
        printf(".");
        total_cnt += read_pkt_cnt;
        if (total_cnt == limit_cnt) break;
        readlen = fread(filebuf, 1, BUF_SIZE, infile);
    }
    printf("\n");
    if (total_cnt != limit_cnt) {
        fprintf(stderr, "processing got unexpected error\n");
        perror(argv[0]);
    }

    printf("\ntotal prcessed : %d\n", total_cnt);

    fclose(infile);
    fflush(outfile);
    fclose(outfile);

    return 0;
}

