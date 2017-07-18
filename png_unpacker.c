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

/* Other PNG constants as defined by the specification */
const char *g_color_types[] =
    {
        [0] = "Greyscale",
        [2] = "Truecolor",
        [3] = "Indexed-color",
        [4] = "Greyscale with alpha",
        [6] = "Truecolor with alpha"
    };

const char *g_comp_methods[] =
    {
        [0] = "Deflate/Inflate with sliding window at most 32768"
    };

const char *g_filter_methods[] =
    {
        [0] = "Adaptive Filtering with 5 basic filter types"
    };

const char *g_interlace_methods[] =
    {
        [0] = "None",
        [1] = "Adam7"
    };


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
    struct chunk_hdr **addrs;
    unsigned int count;
};

struct chunk_ihdr {
    uint32_t width;
    uint32_t height;
    uint8_t bit_depth;
    uint8_t color_type;
    uint8_t comp_method;
    uint8_t filter_method;
    uint8_t interlace_method;
} __attribute__((packed));

struct chunk_plte {
    struct {
        uint8_t red;
        uint8_t blue;
        uint8_t green;
    }pentry[0];
} __attribute__((packed));

struct infdef_hdr {
    uint8_t zlib_comp_method;
    uint8_t flags;
    uint8_t data_blocks;
    uint8_t check_value;
} __attribute__((packed));


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


void png_chunk_hdr_dump(struct chunk_hdr *chunk)
{
    switch(chunk->type){
        case PNG_CHUNK_IHDR:
        {
            struct chunk_ihdr *ihdr = (struct chunk_ihdr *)chunk->data;

            printf("IHDR chunk:\n");
            printf("\tWidth:           %u\n", swap32(ihdr->width));
            printf("\tHeight:          %u\n", swap32(ihdr->height));
            printf("\tBitDepth:        %u\n", ihdr->bit_depth);
            printf("\tColorType:       %u:\t%s\n", ihdr->color_type, g_color_types[ihdr->color_type]);
            printf("\tCompMethod:      %u:\t%s\n", ihdr->comp_method, g_comp_methods[ihdr->comp_method]);
            printf("\tFilterMethod:    %u:\t%s\n", ihdr->filter_method, g_filter_methods[ihdr->filter_method]);
            printf("\tInterlaceMethod: %u:\t%s\n", ihdr->interlace_method, g_interlace_methods[ihdr->interlace_method]);
            break;
        }

        case PNG_CHUNK_PLTE:
            printf("PLTE chunk:\n");
            printf("\t%u entries\n", swap32(chunk->len)); 
            break;

        case PNG_CHUNK_IDAT:
        {
            struct infdef_hdr *zhdr = (struct infdef_hdr *)chunk->data;
           
            printf("IDAT chunk:\n");
            printf("\t%u bytes\n", swap32(chunk->len));
            printf("\tzlibMethod: \t0x%x\n", zhdr->zlib_comp_method);
            printf("\tFlags:      \t0x%x\n", zhdr->flags);
            printf("\tDataBlocks: \t0x%x\n", zhdr->data_blocks);
            printf("\tCheckValue: \t0x%u\n", zhdr->check_value);
            break;
        }

        default:
            printf("Unknown chunk type: 0x%x\n", chunk->type);
            break; 
    }
    printf("\n");
}


int png_process_idhr(struct chunk_hdr *chunk)
{
    struct chunk_ihdr *ihdr = (struct chunk_ihdr *) chunk->data;
    
    /* Header dump */
    png_chunk_hdr_dump(chunk);   
 
    return 0;
}


int png_process_plte(struct chunk_hdr *chunk)
{
    /* Header dump */
    png_chunk_hdr_dump(chunk);   

    return 0;
}


int png_process_idat(struct chunk_hdr *chunk)
{
    /* Header dump */
    png_chunk_hdr_dump(chunk);   

    return 0;
}


int png_walk(struct png_hdr *png, struct chunk_list *chunks)
{
    int ret = 0;
    struct chunk_hdr *chunk = (struct chunk_hdr *)((void *)png + sizeof(struct png_hdr));

    /* Initialize chunk list */
    chunks->addrs = malloc(CHUNK_LIST_SIZE);
    if(NULL == chunks->addrs)
        return -1;
    memset(chunks->addrs, 0, CHUNK_LIST_SIZE);
  
    /* Critical chunks */ 
    while(1){
        /* Save metadata about the chunk */
        chunks->addrs[chunks->count++] = chunk;
        if(0 == chunks->count % CHUNK_LIST_SIZE){
            chunks->addrs = realloc(chunks->addrs, (chunks->count/CHUNK_LIST_SIZE + 1)*CHUNK_LIST_SIZE);
            if(NULL == chunks->addrs){
                printf("Early termination; %d chunks already found: %s\n", chunks->count, strerror(errno));
                ret = -1;
                break;
            }
        }

        /* IEND is _always_ the last chunk */
        if(PNG_CHUNK_IEND == chunk->type)
            break;

        chunk = (struct chunk_hdr *)((void *)chunk + sizeof(struct chunk_hdr) + 4 + swap32(chunk->len)); //FIXME: crc32 +4
    }
    
    return ret;
}


int png_process_chunks(struct chunk_list *chunks)
{
    int i;
    int ret = 0;
    
    printf("Processing %d chunks\n", chunks->count);

    /* Process each discovered chunk */
    for(i=0; i<chunks->count; i++){
        switch(chunks->addrs[i]->type){
            case PNG_CHUNK_IHDR:
                ret = png_process_idhr(chunks->addrs[i]);
                break;

            case PNG_CHUNK_PLTE:
                ret = png_process_idhr(chunks->addrs[i]);
                break;
        
            case PNG_CHUNK_IDAT:
                ret = png_process_idat(chunks->addrs[i]);
                break;

            case PNG_CHUNK_IEND:
                printf("IEND\n");
                break;

            default:
                printf("Unknown\n"); /* Skip unknown chunks */
        }

        if(0 != ret)
            break;
    }

    return ret;
}


int png_decode(const char *file)
{
    int fd, ret = 0;
    struct png_hdr *png;
    struct chunk_list chunks = {0};
    size_t len;

    /* Prepare the PNG for processing */
    if(0 == png_prepare(file, &fd, (void **)&png, &len)){
        if(0 == png_walk(png, &chunks)){
            ret = png_process_chunks(&chunks);
        }else
            ret = -1;
    }
   
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
