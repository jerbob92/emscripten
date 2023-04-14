/*
 * Copyright 2019 The Emscripten Authors.  All rights reserved.
 * Emscripten is available under two separate licenses, the MIT license and the
 * University of Illinois/NCSA Open Source License.  Both these licenses can be
 * found in the LICENSE file.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <malloc.h>
#include <syscall_arch.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#include <emscripten.h>
#include <emscripten/heap.h>
#include <emscripten/console.h>
#include <wasi/api.h>
#include <wasi/wasi-helpers.h>

#include "lock.h"
#include "emscripten_internal.h"

/*
 * WASI support code. These are compiled with the program, and call out
 * using wasi APIs, which can be provided either by a wasi VM or by our
 * emitted JS.
 */

// libc

#ifdef NDEBUG
#define REPORT_UNSUPPORTED(action)
#else
#define REPORT_UNSUPPORTED(action) \
  emscripten_console_error("the program tried to " #action ", this is not supported in standalone mode");
#endif

void abort() {
  _Exit(1);
}

_Static_assert(CLOCK_REALTIME == __WASI_CLOCKID_REALTIME, "must match");
_Static_assert(CLOCK_MONOTONIC == __WASI_CLOCKID_MONOTONIC, "must match");
_Static_assert(CLOCK_PROCESS_CPUTIME_ID == __WASI_CLOCKID_PROCESS_CPUTIME_ID, "must match");
_Static_assert(CLOCK_THREAD_CPUTIME_ID == __WASI_CLOCKID_THREAD_CPUTIME_ID, "must match");

#define NSEC_PER_SEC (1000 * 1000 * 1000)

struct timespec __wasi_timestamp_to_timespec(__wasi_timestamp_t timestamp) {
  return (struct timespec){.tv_sec = timestamp / NSEC_PER_SEC,
                           .tv_nsec = timestamp % NSEC_PER_SEC};
}

int clock_getres(clockid_t clk_id, struct timespec *tp) {
  // See https://github.com/bytecodealliance/wasmtime/issues/3714
  if (clk_id > __WASI_CLOCKID_THREAD_CPUTIME_ID || clk_id < 0) {
    errno = EINVAL;
    return -1;
  }
  __wasi_timestamp_t res;
  __wasi_errno_t error = __wasi_clock_res_get(clk_id, &res);
  if (error != __WASI_ERRNO_SUCCESS) {
    return __wasi_syscall_ret(error);
  }
  *tp = __wasi_timestamp_to_timespec(res);
  return 0;
}

// mmap support is nonexistent. TODO: emulate simple mmaps using
// stdio + malloc, which is slow but may help some things?

// Mark these as weak so that wasmfs does not collide with it. That is, if
// wasmfs is in use, we want to use that and not this.
__attribute__((__weak__)) int _mmap_js(size_t length,
                                       int prot,
                                       int flags,
                                       int fd,
                                       size_t offset,
                                       int* allocated,
                                       void** addr) {
  return -ENOSYS;
}

__attribute__((__weak__)) int _munmap_js(
  intptr_t addr, size_t length, int prot, int flags, int fd, size_t offset) {
  return -ENOSYS;
}

// open(), etc. - we just support the standard streams, with no
// corner case error checking; everything else is not permitted.
// TODO: full file support for WASI, or an option for it
// open()
__attribute__((__weak__))
int __syscall_openat(int dirfd, intptr_t path, int flags, ...) {
  const char* pathname = (const char*)path;
  if (!strcmp(pathname, "/dev/stdin")) {
    return STDIN_FILENO;
  }
  if (!strcmp(pathname, "/dev/stdout")) {
    return STDOUT_FILENO;
  }
  if (!strcmp(pathname, "/dev/stderr")) {
    return STDERR_FILENO;
  }

  // @todo: implement AT_FDCWD properly.
  if (pathname[0] == '/') {
    dirfd = __WASI_FD_ROOT;

    // Remove first char.
    pathname++;
  }

  // Compute rights corresponding with the access modes provided.
  // Attempt to obtain all rights, except the ones that contradict the
  // access mode provided to openat().
  __wasi_rights_t max =
    ~(__WASI_RIGHTS_FD_DATASYNC | __WASI_RIGHTS_FD_READ |
      __WASI_RIGHTS_FD_WRITE | __WASI_RIGHTS_FD_ALLOCATE |
      __WASI_RIGHTS_FD_READDIR | __WASI_RIGHTS_FD_FILESTAT_SET_SIZE);
  switch (flags & O_ACCMODE) {
    case O_RDONLY:
    case O_RDWR:
    case O_WRONLY:
      if ((flags & O_RDONLY) != 0) {
        max |= __WASI_RIGHTS_FD_READ | __WASI_RIGHTS_FD_READDIR;
      }
      if ((flags & O_WRONLY) != 0) {
        max |= __WASI_RIGHTS_FD_DATASYNC | __WASI_RIGHTS_FD_WRITE |
               __WASI_RIGHTS_FD_ALLOCATE |
               __WASI_RIGHTS_FD_FILESTAT_SET_SIZE;
      }
      break;
    case O_EXEC: // O_EXEC => O_PATH => 010000000
    //case O_SEARCH: O_SEARCH => O_PATH => 010000000, both are the same, so causes errors.
      break;
    default:
      errno = EINVAL;
      return -1;
  }

  // Ensure that we can actually obtain the minimal rights needed.
  __wasi_fdstat_t fsb_cur;
  __wasi_errno_t error = __wasi_fd_fdstat_get(dirfd, &fsb_cur);
  if (error != __WASI_ERRNO_SUCCESS) {
    return __wasi_syscall_ret(error);
  }

  // Path lookup properties.
  __wasi_lookupflags_t lookup_flags = 0;
  if ((flags & O_NOFOLLOW) == 0) {
    lookup_flags |= __WASI_LOOKUPFLAGS_SYMLINK_FOLLOW;
  }

  // Open file with appropriate rights.
  __wasi_fdflags_t fs_flags = 0;
  if (flags & O_APPEND) {
    fs_flags |= __WASI_FDFLAGS_APPEND;
  }
  if (flags & O_DSYNC) {
    fs_flags |= __WASI_FDFLAGS_DSYNC;
  }
  if (flags & O_NONBLOCK) {
    fs_flags |= __WASI_FDFLAGS_NONBLOCK;
  }
  if (flags & O_RSYNC) {
    fs_flags |= __WASI_FDFLAGS_RSYNC;
  }
  if (flags & O_SYNC) {
    fs_flags |= __WASI_FDFLAGS_SYNC;
  }

  __wasi_oflags_t oflags = 0;
  if (flags & O_CREAT) {
    oflags |= __WASI_OFLAGS_CREAT;
  }
  if (flags & O_DIRECTORY) {
    oflags |= __WASI_OFLAGS_DIRECTORY;
  }
  if (flags & O_EXCL) {
    oflags |= __WASI_OFLAGS_EXCL;
  }
  if (flags & O_TRUNC) {
    oflags |= __WASI_OFLAGS_TRUNC;
  }

  __wasi_rights_t fs_rights_base = max & fsb_cur.fs_rights_inheriting;
  __wasi_rights_t fs_rights_inheriting = fsb_cur.fs_rights_inheriting;
  __wasi_fd_t newfd;

  error = __wasi_path_open(dirfd, lookup_flags, pathname, strlen(pathname),
                           oflags,
                           fs_rights_base, fs_rights_inheriting, fs_flags,
                           &newfd);
  if (error != __WASI_ERRNO_SUCCESS) {
    return __wasi_syscall_ret(error);
  }

  return newfd;
}

__attribute__((__weak__)) int __syscall_ioctl(int fd, int op, ...) {
  return -ENOSYS;
}

__attribute__((__weak__)) int __syscall_fcntl64(int fd, int cmd, ...) {
  return -ENOSYS;
}

__attribute__((__weak__)) int __syscall_ftruncate64(int fd, uint64_t size) {
  return -ENOSYS;
}

__attribute__((__weak__)) int __syscall_rmdir(intptr_t path) {
  return -ENOSYS;
}

__attribute__((__weak__)) int __syscall_unlinkat(int dirfd, intptr_t path, int flags) {
  return -ENOSYS;
}

static void __wasi_filestat_to_stat(const __wasi_filestat_t *in,
                                  struct stat *out) {
  *out = (struct stat){
    .st_dev = in->dev,
    .st_ino = in->ino,
    .st_nlink = in->nlink,
    .st_size = in->size,
    .st_atim = __wasi_timestamp_to_timespec(in->atim),
    .st_mtim = __wasi_timestamp_to_timespec(in->mtim),
    .st_ctim = __wasi_timestamp_to_timespec(in->ctim),
  };

  // Convert file type to legacy types encoded in st_mode.
  switch (in->filetype) {
    case __WASI_FILETYPE_BLOCK_DEVICE:
      out->st_mode |= S_IFBLK;
      break;
    case __WASI_FILETYPE_CHARACTER_DEVICE:
      out->st_mode |= S_IFCHR;
      break;
    case __WASI_FILETYPE_DIRECTORY:
      out->st_mode |= S_IFDIR;
      break;
    case __WASI_FILETYPE_REGULAR_FILE:
      out->st_mode |= S_IFREG;
      break;
    case __WASI_FILETYPE_SOCKET_DGRAM:
    case __WASI_FILETYPE_SOCKET_STREAM:
      out->st_mode |= S_IFSOCK;
      break;
    case __WASI_FILETYPE_SYMBOLIC_LINK:
      out->st_mode |= S_IFLNK;
      break;
  }
}

__attribute__((__weak__))
int __syscall_fstat64(int fd, intptr_t buf) {
  __wasi_filestat_t internal_stat;
  __wasi_errno_t error = __wasi_fd_filestat_get(fd, &internal_stat);
  if (error != __WASI_ERRNO_SUCCESS) {
    return __wasi_syscall_ret(error);
  }
  __wasi_filestat_to_stat(&internal_stat, (struct stat *) buf);
  return 0;
}

__attribute__((__weak__))
int __syscall_getdents64(int fd, intptr_t dirp, size_t count) {
  intptr_t dirpointer = dirp;
  struct dirent *de;
  de = (void *)(dirpointer);

  // Check if the result buffer is too small.
  if (count / sizeof(struct dirent) == 0) {
    return -EINVAL;
  }

  __wasi_dirent_t entry;

  // Create new buffer size to save same amount of __wasi_dirent_t as dirp records.
  size_t buffer_size = (count / sizeof(struct dirent)) * (sizeof(entry) + 256);
  char *buffer = malloc(buffer_size);
  if (buffer == NULL) {
    return -1;
  }

  size_t buffer_processed = buffer_size;
  size_t buffer_used = buffer_size;
  size_t dirent_processed = 0;

  // Use the cookie of the previous entries, readdir reuses the buffer so
  // a nonzero de->d_off is the cookie of the last readdir call.
  int i;
  struct dirent *checkde;
  __wasi_dircookie_t cookie = 0;
  for (i = 0; i < (count / sizeof(struct dirent)); ++i) {
    checkde = (void *)(dirpointer + (sizeof(struct dirent) * i));

    // Store cookie if it's bigger than the last known.
    if (checkde->d_off > cookie) {
      cookie = checkde->d_off;
    }

    // Reset cookie to 0 so that this offset isn't going to hunt us in later calls.
    checkde->d_off = 0;
  }

  for (;;) {
    // Extract the next dirent header.
    size_t buffer_left = buffer_used - buffer_processed;
    if (buffer_left < sizeof(__wasi_dirent_t)) {
      // End-of-file.
      if (buffer_used < buffer_size) {
        break;
      }

      goto read_entries;
    }
    __wasi_dirent_t entry;
    memcpy(&entry, buffer + buffer_processed, sizeof(entry));

    size_t entry_size = sizeof(__wasi_dirent_t) + entry.d_namlen;
    if (entry.d_namlen == 0) {
      // Invalid pathname length. Skip the entry.
      buffer_processed += entry_size;
      continue;
    }

    // The entire entry must be present in buffer space. If not, read
    // the entry another time. Ensure that the read buffer is large
    // enough to fit at least this single entry.
    if (buffer_left < entry_size) {
      while (buffer_size < entry_size) {
        buffer_size *= 2;
      }
      char *new_buffer = realloc(buffer, buffer_size);
      if (new_buffer == NULL) {
        return -1;
      }
      buffer = new_buffer;
      goto read_entries;
    }

    const char *name = buffer + buffer_processed + sizeof(entry);
    buffer_processed += entry_size;

    // Skip entries that do not fit in the dirent name buffer.
    if (entry.d_namlen > sizeof de->d_name) {
      continue;
    }

    // Skip entries having null bytes in the filename.
    if (memchr(name, '\0', entry.d_namlen) != NULL) {
      continue;
    }

    de->d_ino = entry.d_ino;

    // Map the right WASI type to dirent type.
    // I could not get the dirent.h import to work to use defines.
    switch (entry.d_type) {
      case __WASI_FILETYPE_UNKNOWN:
        de->d_type = 0;
        break;
      case __WASI_FILETYPE_BLOCK_DEVICE:
        de->d_type = 6;
        break;
      case __WASI_FILETYPE_CHARACTER_DEVICE:
        de->d_type = 2;
        break;
      case __WASI_FILETYPE_DIRECTORY:
        de->d_type = 4;
        break;
      case __WASI_FILETYPE_REGULAR_FILE:
        de->d_type = 8;
        break;
      case __WASI_FILETYPE_SOCKET_DGRAM:
        de->d_type = 12;
        break;
      case __WASI_FILETYPE_SOCKET_STREAM:
        de->d_type = 12;
        break;
      case __WASI_FILETYPE_SYMBOLIC_LINK:
        de->d_type = 10;
        break;
      default:
        de->d_type = 0;
        break;
    }

    de->d_off = entry.d_next;
    de->d_reclen = sizeof(struct dirent);
    memcpy(de->d_name, name, entry.d_namlen);
    de->d_name[entry.d_namlen] = '\0';
    cookie = entry.d_next;
    dirent_processed = dirent_processed + sizeof(struct dirent);

    // Can't fit more in my buffer.
    if (dirent_processed + sizeof(struct dirent) > count) {
      break;
    }

    // Set entry to next entry in memory.
    dirpointer = dirpointer + sizeof(struct dirent);
    de = (void *)(dirpointer);

    continue;

    read_entries:;
      // Load more directory entries and continue.
      // TODO: Remove the cast on `buffer` once the witx is updated with char8 support.
      __wasi_errno_t error = __wasi_fd_readdir(fd, (uint8_t *)buffer, buffer_size,
                                               cookie, &buffer_used);
      if (error != 0) {
        errno = error;
        return -1;
      }
      buffer_processed = 0;
  }

  return dirent_processed;
}

int __syscall_newfstatat(int dirfd, intptr_t path, intptr_t buf, int flags) {
  // Convert flags to WASI.
  __wasi_lookupflags_t lookup_flags = 0;
  if ((flags & AT_SYMLINK_NOFOLLOW) == 0) {
    lookup_flags |= __WASI_LOOKUPFLAGS_SYMLINK_FOLLOW;
  }

  const char* pathname = (const char*)path;

  // @todo: implement AT_FDCWD properly.
  if (pathname[0] == '/') {
    dirfd = __WASI_FD_ROOT;

    // Remove first char.
    pathname++;
  }

  __wasi_filestat_t fsb_cur;
  __wasi_errno_t error = __wasi_path_filestat_get(dirfd, lookup_flags, pathname, strlen(pathname), &fsb_cur);
  if (error != __WASI_ERRNO_SUCCESS) {
    return __wasi_syscall_ret(error);
  }

  __wasi_filestat_to_stat(&fsb_cur, (struct stat *) buf);

  return 0;
}

__attribute__((__weak__))
int __syscall_stat64(intptr_t path, intptr_t buf) {
  return __syscall_newfstatat(AT_FDCWD, path, buf, 0);
}

__attribute__((__weak__))
int __syscall_lstat64(intptr_t path, intptr_t buf) {
  return __syscall_newfstatat(AT_FDCWD, path, buf, AT_SYMLINK_NOFOLLOW);
}

__attribute__((__weak__))
int getentropy(void *buffer, size_t length) {
  return __wasi_syscall_ret(__wasi_random_get(buffer, length));
}

__attribute__((__weak__))
int __syscall_getcwd(intptr_t buf, size_t size) {
  // Check if buf points to a bad address.
  if (!buf && size > 0) {
    return -EFAULT;
  }

  // Check if the size argument is zero and buf is not a null pointer.
  if (buf && size == 0) {
    return -EINVAL;
  }

  char res[1]="/";
  int len = 2;

  // Check if the size argument is less than the length of the absolute
  // pathname of the working directory, including null terminator.
  if (len >= size) {
    return -ERANGE;
  }

  // Return value is a null-terminated c string.
  strcpy((char*)buf, res);

  return len;
}

__attribute__((__weak__))
int __syscall_mkdirat(int dirfd, intptr_t path, int mode) {
  const char* pathname = (const char*)path;

  // @todo: implement AT_FDCWD properly.
  if (pathname[0] == '/') {
    dirfd = __WASI_FD_ROOT;

    // Remove first char.
    pathname++;
  }

  __wasi_errno_t error = __wasi_path_create_directory(dirfd, pathname, strlen(pathname));
  if (error != 0) {
    errno = error;
    return -1;
  }
  return 0;
}

// Emscripten additions

// Should never be called in standalone mode
void emscripten_memcpy_big(void *restrict dest, const void *restrict src, size_t n) {
  __builtin_unreachable();
}

size_t emscripten_get_heap_max() {
  // In standalone mode we don't have any wasm instructions to access the max
  // memory size so the best we can do (without calling an import) is return
  // the current heap size.
  return emscripten_get_heap_size();
}

int emscripten_resize_heap(size_t size) {
#ifdef EMSCRIPTEN_MEMORY_GROWTH
  size_t old_size = __builtin_wasm_memory_size(0) * WASM_PAGE_SIZE;
  assert(old_size < size);
  ssize_t diff = (size - old_size + WASM_PAGE_SIZE - 1) / WASM_PAGE_SIZE;
  size_t result = __builtin_wasm_memory_grow(0, diff);
  if (result != (size_t)-1) {
    // Success, update JS (see https://github.com/WebAssembly/WASI/issues/82)
    emscripten_notify_memory_growth(0);
    return 1;
  }
#endif
  return 0;
}

double emscripten_get_now(void) {
  return (1000 * clock()) / (double)CLOCKS_PER_SEC;
}

__attribute__((__weak__))
void _emscripten_throw_longjmp() {
  REPORT_UNSUPPORTED(call longjmp);
  abort();
}

__attribute__((__weak__))
int _setitimer_js(int which, double timeout) {
  REPORT_UNSUPPORTED(set itimer);
  abort();
}

// C++ ABI

// Emscripten disables exception catching by default, but not throwing. That
// allows users to see a clear error if a throw happens, and 99% of the
// overhead is in the catching, so this is a reasonable tradeoff.
// For now, in a standalone build just terminate.
//
// Define these symbols as weak so that when we build with exceptions
// enabled (using wasm-eh) we get the real versions of these functions
// as defined in libc++abi.

__attribute__((__weak__))
void __cxa_throw(void* ptr, void* type, void* destructor) {
  REPORT_UNSUPPORTED(throw an exception);
  abort();
}

// WasmFS integration. We stub out file preloading and such, that are not
// expected to work anyhow.

size_t _wasmfs_get_num_preloaded_files() { return 0; }

size_t _wasmfs_get_num_preloaded_dirs() { return 0; }

int _wasmfs_get_preloaded_file_size(int index) { return 0; }

int _wasmfs_get_preloaded_file_mode(int index) { return 0; }

void _wasmfs_copy_preloaded_file_data(int index, void* buffer) {}

void _wasmfs_get_preloaded_parent_path(int index, void* buffer) {}

void _wasmfs_get_preloaded_child_path(int index, void* buffer) {}

void _wasmfs_get_preloaded_path_name(int index, void* buffer) {}

// Import the VM's fd_write under a different name. Then we can interpose in
// between it and WasmFS's fd_write. That is, libc calls fd_write, which WasmFS
// implements. And WasmFS will forward actual writing to stdout/stderr to the
// VM's fd_write. (This allows WasmFS to do work in the middle, for example, it
// could support embedded files and other functionality.)
__attribute__((import_module("wasi_snapshot_preview1"),
               import_name("fd_write"))) __wasi_errno_t
imported__wasi_fd_write(__wasi_fd_t fd,
                        const __wasi_ciovec_t* iovs,
                        size_t iovs_len,
                        __wasi_size_t* nwritten);

// Write a buffer + a newline.
static void wasi_writeln(__wasi_fd_t fd, const char* buffer) {
  struct __wasi_ciovec_t iovs[2];
  iovs[0].buf = (uint8_t*)buffer;
  iovs[0].buf_len = strlen(buffer);
  iovs[1].buf = (uint8_t*)"\n";
  iovs[1].buf_len = 1;
  __wasi_size_t nwritten;
  imported__wasi_fd_write(fd, iovs, 2, &nwritten);
}

void _emscripten_out(const char* text) { wasi_writeln(1, text); }

void _emscripten_err(const char* text) { wasi_writeln(2, text); }

// In the non-standalone build we define this helper function in JS to avoid
// signture mismatch issues.
// See: https://github.com/emscripten-core/posixtestsuite/issues/6
void __call_sighandler(sighandler_t handler, int sig) {
  handler(sig);
}
