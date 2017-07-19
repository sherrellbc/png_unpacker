#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
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

#define CHUNK_LIST_SIZE    (sizeof(struct chunk_hdr)*10)

/* Other PNG constants as defined by the specification (RFC2083) */
const char *g_png_color_types[] =
    {
        [0] = "Greyscale",
        [2] = "Truecolor",
        [3] = "Indexed-color",
        [4] = "Greyscale with alpha",
        [6] = "Truecolor with alpha"
    };

const char *g_png_comp_methods[] =
    {
        [0] = "Deflate/Inflate with sliding window at most 32768"
    };

const char *g_png_filter_methods[] =
    {
        [0] = "Adaptive Filtering with 5 basic filter types"
    };

const char *g_png_interlace_methods[] =
    {
        [0] = "None",
        [1] = "Adam7"
    };

/* zlib constants as defined by the specification (RFC1950) */
const char *g_zlib_comp_methods[] =
    {
        [8]  = "Deflate/Inflate",
        [15] = "Reserved"
    };

const char *g_zlib_flevels[] =
    {
        [0] = "Fastest",
        [1] = "Fast",
        [2] = "Default",
        [3] = "Max compression; slowest"
    };

const char *g_zlib_deflate_comp_modes[] =
    {
        [0] = "No Compression",
        [1] = "Compressed with fixed/static Huffman codes",
        [2] = "Compressed with dynamic (encoded) Huffman codes",
        [3] = "Reserved; ERROR"
    };

const char *g_common_invalid_str = "INVALID! ERROR";

struct png_hdr {
    uint32_t magic;
    uint32_t stops;
} __attribute__((packed));

struct chunk_hdr {
    uint32_t len;
    uint32_t type;
    uint8_t data[0];
//    uint32_t crc32;   /* Although present, it comes after the variable number of data above */
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


struct zlib_hdr {
    struct {
        union {
            uint8_t word;
            struct {
                /* 
                 * CM    (Compression method)   : 0:3
                 * CINFO (Compression info)     : 4:7
                 */
                uint8_t cm      :4;
                uint8_t cinfo   :4;
            };
        };
    }zlib_comp_method;

    struct {
        union {
            uint8_t word;
            struct {
                /* 
                 * FCHECK (Check bits)          : 0:4
                 * FDICT  (Preset Dictionary)   : 5
                 * FLEVEL (Compression Level)   : 6:7
                 */
                uint8_t fcheck  :5;
                uint8_t fdict   :1;
                uint8_t flevel  :2; 
            };
       }; 
    }flags;

    uint8_t data_blocks[0];
//    uint8_t adler32; /* Although present, it comes after the variable number of data_blocks above */
} __attribute__((packed));

//struct zlib_deflate_data {
//    union {
//        uint8_t data; 
//        struct {
//        /*
//         * BFINAL (Final block)         : 0
//         * BTYPE  (Type of compression) : 1:2
//         */
//            uint8_t bfinal:1, btype:2, :5;
//        };
//    };
//} __attribute__((packed));


uint32_t swap32(uint32_t val);
inline uint32_t swap32(uint32_t val)
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
    void *map;
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
        printf("ERROR: Not a PNG file\n");
        close(lfd);
        munmap(map, img_stat.st_size);
        return -1;
    }

    *fd = lfd;
    *img = map;
    *len = img_stat.st_size;
    return 0;
}


int png_process_idhr(struct chunk_hdr *chunk, uint8_t **buf, int *len)
{
    struct chunk_ihdr *ihdr = (struct chunk_ihdr *)chunk->data;

    printf("\nIHDR chunk:\n");
    printf("\tWidth           :\t%u\n", swap32(ihdr->width));
    printf("\tHeight          :\t%u\n", swap32(ihdr->height));
    printf("\tBitDepth        :\t%u\n", ihdr->bit_depth);
    printf("\tColorType       :\t%u\t%s\n", ihdr->color_type, g_png_color_types[ihdr->color_type]);
    printf("\tCompMethod      :\t%u\t%s\n", ihdr->comp_method, g_png_comp_methods[ihdr->comp_method]);
    printf("\tFilterMethod    :\t%u\t%s\n", ihdr->filter_method, g_png_filter_methods[ihdr->filter_method]);
    printf("\tInterlaceMethod :\t%u\t%s\n", ihdr->interlace_method, g_png_interlace_methods[ihdr->interlace_method]);

    /* Based on what we know about the image, roughly allocate enough memory for it */
    *len = swap32(ihdr->width)*swap32(ihdr->height)*5;    /* 3 for RGB and 2 extra for growth room */
    *buf = malloc(*len);
    if(NULL == *buf)
        return -1;   

    memset(*buf, 0, *len);    
    printf("Allocated %d bytes\n", *len);
    return 0;
}


int png_process_plte(struct chunk_hdr *chunk)
{
    printf("\nPLTE chunk:\n");
    printf("\t%u entries\n", swap32(chunk->len)); 

    return 0;
}


int png_inflate_chunk(uint8_t *dest, int dlen, uint8_t *src, int slen)
{
    z_stream infstream;
    int ret, bytes_processed;

    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = 0;
    infstream.next_in = Z_NULL; 
    ret = inflateInit(&infstream);
    if(Z_OK != ret){
        printf("Failed to initialize inflate engine\n");
        return -1;
    }

    bytes_processed = 0; 
    do{
        infstream.avail_in = slen - bytes_processed;
        infstream.next_in = src + bytes_processed;
        do{
            infstream.avail_out = dlen - bytes_processed;
            infstream.next_out = dest + bytes_processed;

            ret = inflate(&infstream, Z_NO_FLUSH);
            switch (ret) {
                case Z_NEED_DICT:
                    ret = Z_DATA_ERROR;
                case Z_DATA_ERROR:
                case Z_MEM_ERROR:
                    break;
            }

            bytes_processed += (dlen - bytes_processed) - infstream.avail_out;
        }while(infstream.avail_out == 0);
    }while(Z_STREAM_END != ret);

    inflateEnd(&infstream);
    return (ret == Z_STREAM_END) ? bytes_processed : -1;
}


int png_process_idat(struct chunk_hdr *chunk, uint8_t *buf, int len)
{
    static int is_first_idat = 1;
    struct zlib_hdr *zhdr = (struct zlib_hdr *)chunk->data;
    struct zlib_deflate_data *zdeflate = ((struct zlib_deflate_data *) &zhdr->data_blocks[0]);

    int inflate_len;
    uint32_t adler;
    uint32_t adler_ref = *(uint32_t*)(((void*)zhdr)+swap32(chunk->len)-4);  /* -4 to get to the start of the adler32 checksum in the buffer */
    uint32_t crc; 
    uint32_t crc_ref = *(uint32_t *)(((void *)&chunk->data) + swap32(chunk->len));
    uint8_t cm =         zhdr->zlib_comp_method.cm;
    uint8_t cinfo =      zhdr->zlib_comp_method.cinfo;
    uint8_t fcheck =     zhdr->flags.fcheck;
    uint8_t fdict =      zhdr->flags.fdict;
    uint8_t flevel =     zhdr->flags.flevel;
    uint16_t check =   ((zhdr->zlib_comp_method.word) << 8 | zhdr->flags.word) % 31;

    printf("\nIDAT chunk:\n");

    /* Verify crc32 (returned as big-endian) */
    crc = crc32(0, Z_NULL, 0);
    crc = crc32(crc, (void *)&chunk->type, swap32(chunk->len)+4);   /* +4 to include length of the "type" field */
    if(crc_ref != swap32(crc)){
        printf("Invalid CRC; ERROR!\n");
        return -1;
    }
    printf("\tCRC Validated 0x%x == 0x%x\n", crc_ref, swap32(crc));

    if(1 == is_first_idat){
        /* 
         * -- zlib Header --
         * Compression Method
         * Compression info 
         * Checksum of CM + Flags is %31
         * What kind of dictionary was used for the compression?
         * How rigorous was the compression?
         */
        printf("\tzlib:\n");
        printf("\t\tCM     (4):\t0x%.2x\t%s\n", cm, 
            (cm < sizeof(g_zlib_comp_methods)/sizeof(char*)) ? g_zlib_comp_methods[cm] : g_common_invalid_str);
        printf("\t\tCINFO  (4):\t0x%.2x\tWindowSize %.0f\n", cinfo, pow(2,cinfo+8));
        printf("\t\tFCHECK (5):\t0x%.2x\t%s\n", fcheck, check ? g_common_invalid_str : "Valid");
        printf("\t\tFDICT  (1):\t0x%.2x\t%s\n", fdict, fdict ? g_common_invalid_str : "No preset dictionary"); //FIXME: If set, the next 4 bytes are dictionary ID
        printf("\t\tFLEVEL (2):\t0x%.2x\t%s\n", flevel,
            (flevel < sizeof(g_zlib_flevels)/sizeof(char*)) ? g_zlib_flevels[flevel] : g_common_invalid_str);
    }else
        printf("Appending bytes to previous IDAT block\n"); //TODO: This is not actually implemented (FAIL if > 1 IDAT chunk)


    /* 
     * -- Actual nested image data --
     * How is this current data block compressed?
     * Is this the final data block?
     */
    printf("\n\t\tDataBlocks (%d bytes)\n", swap32(chunk->len));

    /* Inflate the data block of the current IDAT chunk */
    inflate_len = png_inflate_chunk(buf, len, (uint8_t *) zhdr, swap32(chunk->len));
    if(-1 == inflate_len){
        printf("Error occurred while inflating .. \n");
        return -1;
    }

    /* Verify Adler32 of inflated data (returned as big-endian) */   
    adler = adler32(0, Z_NULL, 0);
    adler = adler32(adler, buf, inflate_len);
    if(adler_ref != swap32(adler)){
        printf("Invalid deflate Adler32; ERROR!\n");
        return -1;
    }
    printf("\t\t\tAdler32 Validated 0x%x == 0x%x\n", adler_ref, swap32(adler));
    printf("\t\t\tInflated data length :\t%d\n", inflate_len);
    printf("\t\t\tCompression Ratio    :\t%.2f\n", inflate_len/(float)swap32(chunk->len));

    //TODO: Parse/remove filters

    is_first_idat = 0;
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
                /* Reallocation failed, but the original memory remains intact */
                printf("Early termination; %d chunks already found: %s\n", chunks->count, strerror(errno));
                ret = -1;
                break;
            }
        }

        /* IEND is _always_ the last chunk (or should be) */
        if(PNG_CHUNK_IEND == chunk->type)
            break;

        chunk = (struct chunk_hdr *)((void *)chunk + sizeof(struct chunk_hdr) + 4 + swap32(chunk->len)); //FIXME: crc32 +4
    }
    
    return ret;
}


int png_process_chunks(struct chunk_list *chunks)
{
    uint8_t *buf;
    int i, len;
    int ret = 0;
    
    /* Process each discovered chunk */
    for(i=0; i<chunks->count; i++){
        switch(chunks->addrs[i]->type){
            case PNG_CHUNK_IHDR:
                ret = png_process_idhr(chunks->addrs[i], &buf, &len);
                break;

            case PNG_CHUNK_PLTE:
                ret = png_process_plte(chunks->addrs[i]);
                break;
        
            case PNG_CHUNK_IDAT:
                ret = png_process_idat(chunks->addrs[i], buf, len);
                break;

            case PNG_CHUNK_IEND:
                printf("Processed %d chunks\n", i);
                break;

            default:
                printf("Unhandled chunk type: 0x%x \"%c%c%c%c\"\n", chunks->addrs[i]->type,
                    ((char *)&chunks->addrs[i]->type)[0], ((char *)&chunks->addrs[i]->type)[1], 
                    ((char *)&chunks->addrs[i]->type)[2], ((char *)&chunks->addrs[i]->type)[3]);
                break;
        }

        if(0 != ret)
            break;
    }

    //FIXME: Freeing for now to prevent memory leak, but what to do with buf here?
    free(buf);
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
    /* Keep it simple; the second argument is the PNG file */
    if(argc != 2){
        printf("Usage: %s <*.png>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    return png_decode(argv[1]);
}
