#include <stdio.h>
#include <string.h>

#define BUF_SIZE 1024*188
#define TS_SYNC_BYTE 0x47
#define PID_LIST_SIZE 64

unsigned short PidList[PID_LIST_SIZE] = {0};
unsigned char  PidNum = 0;

int PidCompare(const void *v1,const void *v2) {
    unsigned short* pid1 = (unsigned short*)v1;
    unsigned short* pid2 = (unsigned short*)v2;
    if (pid1<pid2) return 1;
    else if (pid1==pid2) return 0;
    return -1;
}

int main(int argc, char* argv[])
{
    FILE* infile;
    int readlen, idx, pidx, pid, procbyte;
    unsigned char Buf[BUF_SIZE];

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

    memset(PidList, 0, sizeof(PidList));
    memset(&PidNum, 0, sizeof(PidNum));

    readlen = fread(Buf, 1, BUF_SIZE, infile);
    while (readlen > 0) {
        if (readlen%188 != 0) {
            fprintf(stderr, "readlen error %d != 188*N\n", readlen);
            break;
        }
        for (idx=0 ; idx<readlen ; idx+=188) {
            if (Buf[idx] != TS_SYNC_BYTE) {
                fprintf(stderr, "sync byte error\n");
                readlen = -1;
                break;
            }
            pid = ((Buf[idx+1]<<8) | Buf[idx+2]) & 0x1FFF;
            //printf("pid = %d\n", pid);
            for (pidx=0 ; pidx<PidNum && pid!=PidList[pidx] ; ++pidx)
                ; // empty
            if (pidx == PidNum) {
                if (PID_LIST_SIZE == PidNum) {
                    fprintf(stderr, "PidList full error\n");
                    readlen = -1;
                    break;
                }
                printf("new pid = %d\n", pid);
                PidList[PidNum] = pid;
                ++PidNum;
                // TODO: change to the insertion sort
                //qsort(PidList, PidNum, sizeof(PidList[0]), PidCompare);
            }
        }
        if (readlen > 0) {
            procbyte += readlen;
            readlen = fread(Buf, 1, BUF_SIZE, infile);
        }
    }
    if (readlen < 0) {
        perror(argv[0]);
    }
    fclose(infile);

    puts("======= [ Found Pids ] =======");
    printf("Processed bytes : %d\n", procbyte);
    printf("Total Pids : %d\n", PidNum);
    for (pidx=0 ; pidx<PidNum ; ++pidx) {
        printf("%2d : %4hu 0x%-4hx\n", pidx, PidList[pidx], PidList[pidx]);
    }

    return 0;
}
