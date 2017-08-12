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
#define PNG_CHUNK_tIME  0x454d4974 /* 'E' 'M' 'I' 't'  */
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

const char *g_png_filter_types[] =
    {
        [0] = "None",
        [1] = "Sub",
        [2] = "Up",
        [3] = "Average",
        [4] = "Paeth"
    };

enum png_filter_type {
    PNG_FILTER_NONE = 0,
    PNG_FILTER_SUB,
    PNG_FILTER_UP,
    PNG_FILTER_AVERAGE,
    PNG_FILTER_PAETH,
};

const char *g_png_interlace_methods[] =
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
//    uint32_t crc32;   /* Although present, it comes after the variable number of data above */
} __attribute__((packed));

struct chunk_list {
    struct chunk_hdr **addrs;
    unsigned int count;
};

struct chunk_IHDR {
    uint32_t width;
    uint32_t height;
    uint8_t bit_depth;
    uint8_t color_type;
    uint8_t comp_method;
    uint8_t filter_method;
    uint8_t interlace_method;
} __attribute__((packed));

struct chunk_tIME {
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
} __attribute__((packed));

struct chunk_PLTE {
    struct {
        uint8_t red;
        uint8_t blue;
        uint8_t green;
    }pentry[0];
} __attribute__((packed));

struct png_img {
    struct chunk_IHDR *ihdr;
    uint8_t *data;
    uint8_t *data_next;     /* A pointer into the data buffer indictating the next available slot */
    int buf_len;            /* Total available length in data buffer */
    int data_len;           /* Currently _used_ length in data buffer */
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

/* Common data */
const char *g_common_invalid_str = "INVALID! ERROR";

uint32_t swap32(uint32_t val);
uint16_t swap16(uint16_t val);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
inline uint32_t swap32(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF ); 
    return (val << 16) | (val >> 16);
}


inline uint16_t swap16(uint16_t val)
{
    return ((val >> 8) | val << 8);
}
#else
inline uint32_t swap32(uint32_t val){ return val };
inline uint16_t swap16(uint16_t val){ return val };
#endif

int is_png(void *img);
inline int is_png(void *img)
{
    return (PNG_HDR_SIG == ((struct png_hdr *)img)->magic);
}


int png_print_data(struct png_img *png, int offset, int len)
{
    uint8_t *buf = (uint8_t *) (((void *)png->data + offset));
    int width = swap32(png->ihdr->width);
    int i, line;

    for(i=0,line=0; i<len; i+=3){
        if(0 == i%width){
            printf("\n[%d]\t", line++);
        }
        printf("[%0.2x%0.2x%0.2x] ", buf[i+line-1], buf[i+1+line-1], buf[i+2+line-1]);
    }
    printf("\n");
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


int png_process_IHDR(struct chunk_hdr *chunk, struct png_img *png)
{
    struct chunk_IHDR *ihdr = (struct chunk_IHDR *)chunk->data;

    printf("\nIHDR chunk:\n");
    printf("\tWidth           :\t%u\n", swap32(ihdr->width));
    printf("\tHeight          :\t%u\n", swap32(ihdr->height));
    printf("\tBitDepth        :\t%u\n", ihdr->bit_depth);
    printf("\tColorType       :\t%u\t%s\n", ihdr->color_type, g_png_color_types[ihdr->color_type]);
    printf("\tCompMethod      :\t%u\t%s\n", ihdr->comp_method, g_png_comp_methods[ihdr->comp_method]);
    printf("\tFilterMethod    :\t%u\t%s\n", ihdr->filter_method, g_png_filter_methods[ihdr->filter_method]);
    printf("\tInterlaceMethod :\t%u\t%s\n", ihdr->interlace_method, g_png_interlace_methods[ihdr->interlace_method]);

    /* Based on what we know about the image, roughly allocate enough memory for it */
    png->ihdr = ihdr;
    png->buf_len = swap32(ihdr->width)*swap32(ihdr->height)*5;    /* 3 for RGB and 2 extra for growth room */
    png->data = malloc(png->buf_len);
    if(NULL == png->data)
        return -1;   

    memset(png->data, 0, png->buf_len);
    png->data_next = png->data;
    png->data_len = 0;
    printf("Allocated %d bytes\n", png->buf_len);
    return 0;
}


int png_process_tIME(struct chunk_hdr *chunk, struct png_img *png)
{ (void)png;

    const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    struct chunk_tIME *time = (struct chunk_tIME *)chunk->data;
    printf("\ntIME chunk\n\tLast modified: %s %u, %u %0.2u:%0.2u:%0.2u UTC\n\n", 
        months[time->month-1], time->day, swap16(time->year), time->hour, time->minute, time->second);
    return 0;
}


int png_process_PLTE(struct chunk_hdr *chunk, struct png_img *png)
{ (void)png;

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


/*
 * Unfilter image data in place
 * @param buf         : Buffer containing filter-encoded image data
 * @param len         : Length of buffer data to unfilter
 * @param img_width   : Column width for the final image
 * @return            : New length of data after removing filter encodings
 * 
 * Notes: If multiple IDAT structures are being appended, this function is likely to be
 * called more than once. However, its current implementation does not support this as
 * it will be necessary to know if the current subsection of the image (some series of lines)
 * is the image's true line zero. This line index has special implications for unfiltering
 *
 * Notes: "pix" may not be a good name for the filter operations
 *        It may be more clear if we just define a simple RGB structure and walk the data this way
 *        TODO: There is huge penalty later for invoking write syscalls, we should just reallocate memory
 *        here to fit the new size of the original data (after removing the 1 byte filter encoding)
 */
int png_unfilter(uint8_t *buf, int len, int img_width)
{
    int encoded_width = img_width*3+1;   /* +1 byte for encoded filter type; x3 for RGB color space */
    int decoded_width = encoded_width-1;
    int line_count = len/encoded_width;
    uint8_t filter_type;
    uint8_t (*unfiltered_img)[encoded_width] = (uint8_t(*)[encoded_width]) buf;

    printf("Line filter modes:\n");
    for(int line=0; line<line_count; line++){   
        filter_type = unfiltered_img[line][0];
        printf("Line %4d: FilterType[%d]=", line, unfiltered_img[line][0]);

        /* Check for invalid filter types (indicates malformed encoding) */
        if(filter_type >= sizeof(g_png_filter_types)/sizeof(char*)){
            printf("%s\n", g_common_invalid_str);
            return -1;
        }
        printf("%s\n", g_png_filter_types[unfiltered_img[line][0]]);

        /* Copy the filtered data over top the filter encoding byte to realign (suboptimal, but easier access) */
        memmove(&unfiltered_img[line][0], &unfiltered_img[line][1], decoded_width);

        /* Note that unfiltering works on groups of 3 RGB pixels; not bytes individually */
        switch(filter_type){
            case PNG_FILTER_SUB:
                /* Filter SUB starts at index 1 because pixels "to the left" of index 0 are assumed zero */
                for(int pix = 3; pix<decoded_width; pix+=3){
                    unfiltered_img[line][pix]   += unfiltered_img[line][pix-3];
                    unfiltered_img[line][pix+1] += unfiltered_img[line][pix-2];
                    unfiltered_img[line][pix+2] += unfiltered_img[line][pix-1];
                }
                break;
            
            case PNG_FILTER_UP:
                if(0 != line_count){
                    /* Filter UP starts at row 1 because pixels "above" index 0 are assumed zero */
                    for(int pix = 0; pix<decoded_width; pix+=3){
                        unfiltered_img[line][pix]   += unfiltered_img[line-1][pix];
                        unfiltered_img[line][pix+1] += unfiltered_img[line-1][pix+1];
                        unfiltered_img[line][pix+2] += unfiltered_img[line-1][pix+2];
                    }
                }
                break;
            
            case PNG_FILTER_NONE:
                /* This case is handled with the memove execution earlier */
                break;

            case PNG_FILTER_PAETH:
            {
                int a, b, c;
                int pa, pb, pc;

                /* For each R, G, and B comparisons independently */
                for(int color_index = 0; color_index<3; color_index++){
                    for(int pix = 0; pix<decoded_width; pix+=3){
                        /* Check for special condition of first line and first column */
                        if(0 == pix){
                            a = 0;
                            c = 0;
                            (0 == line) ? (b = 0) : (b = unfiltered_img[line-1][pix+color_index]);
                        }else{
                            if(0 == line){
                                b = 0;
                                c = 0;
                            }else{
                                b = unfiltered_img[line-1][pix+color_index];
                                c = unfiltered_img[line-1][pix-3+color_index];
                            }
                            a = unfiltered_img[line][pix-3+color_index];
                        }

                        pa = abs(b-c);
                        pb = abs(a-c);
                        pc = abs(a+b-2*c);
                        
                        if( (pa <= pb) && (pa <= pc) ){
                            unfiltered_img[line][pix+color_index] += a;
                        }else if(pb <= pc){
                            unfiltered_img[line][pix+color_index] += b;
                        }else{
                            unfiltered_img[line][pix+color_index] += c;
                        }
                    }
                }

                break;
            }

            case PNG_FILTER_AVERAGE:
            {
                int a,b;

                /* Filter UP starts at row 1 because pixels "above" index 0 are assumed zero */
                for(int color_index = 0; color_index<3; color_index++){
                    for(int pix = 0; pix<decoded_width; pix+=3){
                        (0 == pix) ? (a = 0) : (a = unfiltered_img[line][pix-3+color_index]);
                        (0 == line) ? (b = 0) : (b = unfiltered_img[line-1][pix+color_index]);
                        unfiltered_img[line][pix+color_index] += floor( (a+b)/2.0 ); 
                    }
                }
                break;
            }

            default:
                /* We already checked the proper range for filter_type above, so print it here */
                printf("Filter method [%d: %s] not yet implemented\n", filter_type, g_png_filter_types[filter_type]);
                break;
        }
    }

    printf("\n");
    return line_count*(encoded_width-1);  /* Basically len - 1 byte per line for the filter encoding */
}


int png_process_IDAT(struct chunk_hdr *chunk, struct png_img *png)
{
    static int is_first_idat = 1;
    struct zlib_hdr *zhdr = (struct zlib_hdr *)chunk->data;
    struct zlib_deflate_data *zdeflate = ((struct zlib_deflate_data *) &zhdr->data_blocks[0]);

    int inflate_len, unfiltered_len;
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
    }else{
        printf("ERROR: Should append bytes to previous IDAT block\n"); //TODO: This is not actually implemented (FAIL if > 1 IDAT chunk)
        return -1;
    }

    /* Actual nested image data */
    printf("\n\t\tDataBlocks (%d bytes)\n", swap32(chunk->len));

    /* Inflate the data block of the current IDAT chunk */
    inflate_len = png_inflate_chunk(png->data_next, png->buf_len - png->data_len, (uint8_t *) zhdr, swap32(chunk->len));
    if(-1 == inflate_len){
        printf("Error occurred while inflating .. \n");
        return -1;
    }

    /* Verify Adler32 of inflated data (returned as big-endian) */   
    adler = adler32(0, Z_NULL, 0);
    adler = adler32(adler, png->data_next, inflate_len);
    if(adler_ref != swap32(adler)){
        printf("Invalid deflate Adler32; ERROR!\n");
        return -1;
    }
    printf("\t\t\tAdler32 Validated 0x%x == 0x%x\n", adler_ref, swap32(adler));
    printf("\t\t\tInflated data length :\t%d\n", inflate_len);
    printf("\t\t\tCompression Ratio    :\t%.2f\n", inflate_len/(float)swap32(chunk->len));

    /* Parse/remove filters and any associated encoding data; return _actual_ data length consumed */
    unfiltered_len = png_unfilter(png->data, inflate_len, swap32(png->ihdr->width));
    if(-1 == unfiltered_len) 
        return -1;

//    png_print_data(png, 0, unfiltered_len);    /* FIXME: Debug dump of the buffer */
    
    /* Validation checks out; update our location pointers and length meta data */
    png->data_next = (uint8_t *)(((void *)png->data) + unfiltered_len);
    png->data_len += unfiltered_len;
    //FIXME: Resize check here for later IDAT structures

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

        chunk = (struct chunk_hdr *)((void *)chunk + sizeof(struct chunk_hdr) + 4 + swap32(chunk->len)); //FIXME: +4 for crc32
    }
    
    return ret;
}


//FIXME: This is absolutely terrible; the underlying method for handling this data buffer should be reallocated to fix the new unfiltered size
// - 1 malloc vs "height" number of write syscalls
int png_write_raw_img(struct png_img *png)
{
    unsigned int line_len = swap32(png->ihdr->width)*3; 
    uint8_t (*img)[line_len+1] = (uint8_t(*)[line_len+1]) png->data;
    
    int fd = open("img.data", O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if(-1 == fd)
        return -1;
    
    for(int line=0; line<swap32(png->ihdr->height); line++){
        if(line_len != write(fd, &img[line][0], line_len))
            printf("Failed to write img file\n");
    }
    
    return close(fd);
}


/* Array of handlers for the various function chunks; this eases the install process for supporting new chunk types */
struct chunk_handler {
    uint32_t type;
    int (*handler)(struct chunk_hdr *chunk, struct png_img *png);
}g_chunk_handlers[] = 
    {
        {
            .type = PNG_CHUNK_IHDR,
            .handler = png_process_IHDR
        },

        {
            .type = PNG_CHUNK_PLTE,
            .handler = png_process_PLTE
        },

        {
            .type = PNG_CHUNK_tIME,
            .handler = png_process_tIME
        },

        {
            .type = PNG_CHUNK_IDAT,
            .handler = png_process_IDAT
        },
    };


int png_process_chunks(struct chunk_list *chunks)
{
    struct png_img png = {0};
    int i,j;
    int ret = 0;
    
    /* Process each discovered chunk */
    for(i=0; i<chunks->count; i++){
        for(j=0; j<sizeof(g_chunk_handlers)/sizeof(struct chunk_handler); j++){
            if(g_chunk_handlers[j].type == chunks->addrs[i]->type){
                ret = g_chunk_handlers[j].handler(chunks->addrs[i], &png);
                break;
            }
        }

        /* Check for the case where no handler was found */
        if(sizeof(g_chunk_handlers)/sizeof(struct chunk_handler) == j){
            /* Special case IEND chunk */
            if(PNG_CHUNK_IEND == chunks->addrs[i]->type){
                printf("Processed %d chunks\n", i);
                break;
            }else{
                printf("Unhandled chunk type: 0x%x \"%c%c%c%c\"\n", chunks->addrs[i]->type,
                    ((char *)&chunks->addrs[i]->type)[0], ((char *)&chunks->addrs[i]->type)[1], 
                    ((char *)&chunks->addrs[i]->type)[2], ((char *)&chunks->addrs[i]->type)[3]);
                continue;
            }
        }

        /* Failure mode check */
        if(0 != ret)
            break;
    }

    png_write_raw_img(&png);
    free(png.data);
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
