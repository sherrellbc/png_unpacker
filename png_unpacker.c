#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <zlib.h>

/* PNG-related magic constants */
#define PNG_HDR_SIG     0x474e5089 /* 'G' 'N' 'P' 0x89 */
#define PNG_CHUNK_IHDR  0x52444849 /* 'R' 'D' 'H' 'I'  */
#define PNG_CHUNK_PLTE  0x45544c50 /* 'E' 'T' 'L' 'P'  */
#define PNG_CHUNK_IDAT  0x54414449 /* 'T' 'A' 'D' 'I'  */
#define PNG_CHUNK_IEND  0x444e4549 /* 'D' 'N' 'E' 'I'  */

#define CHUNK_LIST_SIZE    (sizeof(struct chunk_hdr)*100)

struct png_hdr {
    uint32_t magic;
    uint32_t stops;
} __attribute__((packed));

struct chunk_hdr {
    uint32_t len;
    uint32_t type;
    uint8_t data[0];
} __attribute__((packed));

struct chunk_list {
    struct chunk_hdr *addrs;
    unsigned int count;
};


uint32_t swap32(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}


int is_png(void *img)
{
    return (PNG_HDR_SIG == ((struct png_hdr *)img)->magic);
}


int png_prepare(const char *file, int *fd, void **img, size_t *len)
{
    int lfd;
    uint8_t *map;
    struct stat img_stat;

    /* Collect attribute information about the file before processing */
    lfd = open(file, O_RDONLY);
    if(-1 == lfd)
        return -1;

    if(-1 == fstat(lfd, &img_stat)){
        close(lfd);
        return -1;
    }

    /* Map the file into our address space for simpler processing */ 
    map = mmap(NULL, img_stat.st_size, PROT_READ, MAP_PRIVATE, lfd, 0);
    if(NULL == map){
        close(lfd);
        return -1;
    }

    /* Sanity check to ensure we are working with a PNG file */
    if(1 != is_png(map)){
        close(lfd);
        munmap(map, img_stat.st_size);
        return -1;
    }

    *fd = lfd;
    *img = map;
    *len = img_stat.st_size;
    return 0;
}


int png_walk(struct png_hdr *png, struct chunk_list *chunks)
{
    struct chunk_hdr *chunk = (struct chunk_hdr *)((void *)png + sizeof(struct png_hdr));

    /* Initialize chunk list */
    chunks->addrs = malloc(CHUNK_LIST_SIZE);
    if(NULL == chunks->addrs)
        return -1;
    memset(&chunks->addrs, 0, CHUNK_LIST_SIZE);
  
    /* Critical chunks */ 
    while(1){
        /* Save metadata about the chunk */
        chunks->addrs[chunks->count++] = &chunk;
        if(0 == chunks->count % CHUNK_LIST_SIZE){
            chunks->addrs = realloc(chunks->addrs, (chunks->count/CHUNK_LIST_SIZE + 1)*CHUNK_LIST_SIZE);
            if(NULL == chunks->addrs){
                printf("Early termination; some chunks already found: %s\n", strerror(errno));
                break;
            }
        }

        /* IEND is _always_ the last chunk */
        if(PNG_HDR_IEND == chunk->type)
            break;

        chunk = (struct chunk_hdr *)((void *)chunk + sizeof(struct chunk_hdr) + 4 + swap32(chunk->len)); //FIXME: crc32 +4
    }
    
    printf("Found IEND\n");
    return 0;
}


int png_process_chunks(struct chunk_list *chunks)
{
//        printf("Len=%d, crc=0x%x\n", swap32(chunk->len));
    return -1;
}


int png_decode(const char *file)
{
    int fd, ret = 0;
    struct png_hdr *png;
    struct chunk_list chunks = {0};
    size_t len;

    /* Prepare the PNG for processing */
    if(0 == png_prepare(file, &fd, (void **)&png, &len))
       ret = png_walk(png, &chunks); 
   
    /* Free resources */ 
    if(NULL != chunks.addrs)
        free(chunks.addrs);
    close(fd);
    munmap(png, len);
    return ret;
}


int main(int argc, void **argv)
{
    /* Keep it simple; the second argument in the PNG file */
    if(argc != 2){
        printf("Usage: %s <*.png>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    return png_decode(argv[1]);
}



//    while(1 != done){
//        switch(chunk->type){
//            case PNG_CHUNK_IHDR:
//                printf("IDHR\n");
//                break;
//
//            case PNG_CHUNK_PLTE:
//                printf("PLTE\n");
//                break;
//        
//            case PNG_CHUNK_IDAT:
//                printf("IDAT\n");
//                break;
//
//            case PNG_CHUNK_IEND:
//                printf("IEND\n");
//                done = 1;
//                break;
//
//            default:
//                printf("Unknown\n"); /* Skip unknown chunks */
//        }
