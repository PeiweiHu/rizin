#ifndef R_FILE_H
#define R_FILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rz_util/rz_mem.h>

/* is */
RZ_API bool rz_file_is_abspath(const char *file);
RZ_API bool rz_file_is_c(const char *file);
RZ_API bool rz_file_is_directory(const char *str);
RZ_API bool rz_file_is_regular(const char *str);

RZ_API bool rz_file_truncate(const char *filename, ut64 newsize);
RZ_API ut64 rz_file_size(const char *str);
RZ_API char *rz_file_root(const char *root, const char *path);
RZ_API RMmap *rz_file_mmap(const char *file, bool rw, ut64 base);
RZ_API int rz_file_mmap_read(const char *file, ut64 addr, ut8 *buf, int len);
RZ_API int rz_file_mmap_write(const char *file, ut64 addr, const ut8 *buf, int len);
RZ_API void rz_file_mmap_free(RMmap *m);
RZ_API bool rz_file_chmod(const char *file, const char *mod, int recursive);
RZ_API char *rz_file_temp(const char *prefix);
RZ_API char *rz_file_path(const char *bin);
RZ_API const char *rz_file_basename(const char *path);
RZ_API char *rz_file_dirname(const char *path);
RZ_API char *rz_file_abspath_rel(const char *cwd, const char *file);
RZ_API char *rz_file_abspath(const char *file);
RZ_API ut8 *rz_inflate(const ut8 *src, int srcLen, int *srcConsumed, int *dstLen);
RZ_API ut8 *rz_file_gzslurp(const char *str, int *outlen, int origonfail);
RZ_API char *rz_stdin_slurp(int *sz);
RZ_API char *rz_file_slurp(const char *str, R_NULLABLE size_t *usz);
//RZ_API char *rz_file_slurp_range(const char *str, ut64 off, ut64 sz);
RZ_API char *rz_file_slurp_range(const char *str, ut64 off, int sz, int *osz);
RZ_API char *rz_file_slurp_random_line(const char *file);
RZ_API char *rz_file_slurp_random_line_count(const char *file, int *linecount);
RZ_API ut8 *rz_file_slurp_hexpairs(const char *str, int *usz);
RZ_API bool rz_file_dump(const char *file, const ut8 *buf, int len, bool append);
RZ_API bool rz_file_touch(const char *file);
RZ_API bool rz_file_hexdump(const char *file, const ut8 *buf, int len, int append);
RZ_API bool rz_file_rm(const char *file);
RZ_API bool rz_file_exists(const char *str);
RZ_API bool rz_file_fexists(const char *fmt, ...);
RZ_API char *rz_file_slurp_line(const char *file, int line, int context);
RZ_API char *rz_file_slurp_lines(const char *file, int line, int count);
RZ_API char *rz_file_slurp_lines_from_bottom(const char *file, int line);
RZ_API int rz_file_mkstemp(const char *prefix, char **oname);
RZ_API char *rz_file_tmpdir(void);
RZ_API char *rz_file_readlink(const char *path);
RZ_API bool rz_file_copy (const char *src, const char *dst);
RZ_API RzList* rz_file_globsearch (const char *globbed_path, int maxdepth);
RZ_API RMmap *rz_file_mmap_arch (RMmap *map, const char *filename, int fd);

#ifdef __cplusplus
}
#endif

#endif //  R_FILE_H