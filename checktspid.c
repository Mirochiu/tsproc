#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 1024*188
#define TS_SYNC_BYTE 0x47
#define PID_LIST_SIZE 64

typedef unsigned int pid_t;

typedef struct pid_list_s {
    pid_t* PidList;
    unsigned int PidNum; 
    unsigned int Capacity;
} *PidListHandle;

#define PIDLIST_OPERATION_SUCCEED  0
#define PIDLIST_ERR_INVALID_ARGS  (-1)
#define PIDLIST_ERR_ALLOCATE_MEM  (-2)
#define PIDLIST_ERR_INVALID_TS    (-3)
#define PIDLIST_ERR_LIST_FULL     (-4)

// Args:
// [in]cap      : the capacity of the pid list. Rec=32
// [in]clear    : set all pids to 0 in the list. Rec=0
// [in&out]h    : gave a pointer of the pid list handler. Upon succeeful
//                the function the arg h will got the address of the handler.
// Ret:
// On success, zero is returned. 
// Otherwise, the error code is returned.
int CreatePidList(unsigned int cap, int clear, PidListHandle *h) {
    if (!h) return PIDLIST_ERR_INVALID_ARGS;
    *h = malloc(sizeof(struct pid_list_s));
    if (!*h) return PIDLIST_ERR_ALLOCATE_MEM;
    (*h)->PidList = malloc(sizeof(pid_t)*cap);
    // failure process
    if (!(*h)->PidList) {
        free((*h));
        (*h) = 0;
        return PIDLIST_ERR_ALLOCATE_MEM;
    }
    if (clear) memset((*h)->PidList, 0xffff, sizeof(pid_t)*cap);
    (*h)->PidNum = 0;
    (*h)->Capacity = cap;
    return PIDLIST_OPERATION_SUCCEED;
}

// Args:
// [in&out]h    : destroy the given handler and set to NULL.
void DestroyPidList(PidListHandle *h) {
    if (!h || !*h) return;
    (*h)->Capacity = 0;
    (*h)->PidNum = 0;
    if ((*h)->PidList) {
        free((*h)->PidList);
        (*h)->PidList = 0;
    }
    *h = 0;
}

int DiscoverPidsFromBuffer(PidListHandle hdl, void* buf, unsigned int len) {
    unsigned char *h, *e;
    pid_t *ph, *pe;
    pid_t pid;
    if (!hdl) return PIDLIST_ERR_INVALID_ARGS;
    if (!buf) return PIDLIST_ERR_INVALID_ARGS;
    if (len%188 != 0) return PIDLIST_ERR_INVALID_ARGS;
    // if you doesn't want to reject the length of buf.
    // please remove one line code above and try the following code.
    // len -= len%188;
    h = buf;
    e = h + len;
    while (h != e) {
        if (TS_SYNC_BYTE != *h) return PIDLIST_ERR_INVALID_TS;
        pid = (((*++h)<<8)|*(++h)) & 0x1FFF;
        ph = hdl->PidList;
        pe = hdl->PidList + hdl->PidNum;
        while (ph != pe && *ph < pid) {
            ++ph;
        }
        if (ph==pe || *ph != pid) {
            if (hdl->PidNum >= hdl->Capacity) return PIDLIST_ERR_LIST_FULL; // pidlist full
            printf("found new pid %4hu 0x%-4hX\n", pid, pid);
            if (pe-ph) memmove(ph+1, ph, (pe-ph)*sizeof(pid_t));
            *ph = pid;
            ++hdl->PidNum;
        }
        h += 186;
    }
    return len;
}

int main(int argc, char* argv[])
{
    FILE* infile;
    int readlen, idx, ret, procbyte;
    PidListHandle hdl;
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

    ret = CreatePidList(32, 1, &hdl);
    if (PIDLIST_OPERATION_SUCCEED != ret) {
        fprintf(stderr, "cannot create pid list\n");
        return -1;
    }

    readlen = fread(Buf, 1, BUF_SIZE, infile);
    while (readlen > 0) {
        if (readlen%188 != 0) {
            fprintf(stderr, "readlen error %d != 188*N\n", readlen);
            break;
        }
        ret = DiscoverPidsFromBuffer(hdl, Buf, readlen);
        if (PIDLIST_ERR_LIST_FULL == ret) {
            fprintf(stderr, "PidList is full!, exit\n");
            break;
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
    printf("Total Pids : %d\n", hdl->PidNum);
    for (idx=0 ; idx<hdl->PidNum ; ++idx) {
        printf("%2d : %4hu 0x%-4hX\n", idx+1, hdl->PidList[idx], hdl->PidList[idx]);
    }

    DestroyPidList(&hdl);

    return 0;
}
