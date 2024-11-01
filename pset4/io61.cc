#include "io61.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <climits>
#include <cerrno>
#include <sys/mman.h>

// io61.cc
//    YOUR CODE HERE!


// io61_file
//    Data structure for io61 file wrappers. Add your own stuff.

struct io61_file {
    int fd = -1;     // file descriptor
    int mode;        // open mode (O_RDONLY or O_WRONLY)
    static constexpr off_t buf_size = 8196;
    unsigned char buf[buf_size];
    off_t buf_pos;
    off_t buf_end;
    off_t buf_start;
    size_t size;
    char* memy_buf = nullptr;
    size_t memy_off = 0;
};


// io61_fdopen(fd, mode)
//    Returns a new io61_file for file descriptor `fd`. `mode` is either
//    O_RDONLY for a read-only file or O_WRONLY for a write-only file.
//    You need not support read/write files.

io61_file* io61_fdopen(int fd, int mode) {
    assert(fd >= 0);
    io61_file* f = new io61_file;
    f->fd = fd;
    f->mode = mode;
    if (mode == O_RDONLY) {
        off_t size = io61_filesize(f);
        char* memdata = (char*)mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0);
        if (memdata != (char*)MAP_FAILED) {
            f->memy_buf = memdata;
            f->size = size;
            f->memy_off = 0;
        }
    }
    return f;
}


// io61_close(f)
//    Closes the io61_file `f` and releases all its resources.

int io61_close(io61_file* f) {
    io61_flush(f);
    if (f->memy_buf) {
        munmap(f->memy_buf, f->size);
    }
    int r = close(f->fd);
    delete f;
    return r;
}

// io61_readc(f)
//    Reads a single (unsigned) byte from `f` and returns it. Returns EOF,
//    which equals -1, on end of file or error.
void io61_fill(io61_file* f);
int io61_readc(io61_file* f) {
    assert(f->buf_start <= f->buf_pos && f->buf_pos <= f->buf_end);
    assert(f->buf_end - f->buf_pos <= io61_file::buf_size);
    if(f->memy_buf){
        if(f->memy_off >= (size_t)f->size) {
            return EOF;
        }
        return (unsigned char)f->memy_buf[f->memy_off++];
    }
    if (f->buf_pos == f->buf_end) {
        io61_fill(f);
        if (f->buf_pos == f->buf_end) {
            return EOF;
        }
    }
    return f->buf[f->buf_pos++ - f->buf_start]; 
}


// io61_read(f, buf, sz)
//    Reads up to `sz` bytes from `f` into `buf`. Returns the number of
//    bytes read on success. Returns 0 if end-of-file is encountered before
//    any bytes are read, and -1 if an error is encountered before any
//    bytes are read.
//
//    Note that the return value might be positive, but less than `sz`,
//    if end-of-file or error is encountered before all `sz` bytes are read.
//    This is called a “short read.”


void io61_fill(io61_file* f) {
    assert(f->buf_start <= f->buf_pos && f->buf_pos <= f->buf_end);
    assert(f->buf_end - f->buf_pos <= io61_file::buf_size);
    f->buf_start = f->buf_pos = f->buf_end;
    ssize_t n = read(f->fd, f->buf, io61_file::buf_size);
    if (n >= 0) {
        f->buf_end = f->buf_start + n;
    }
}
ssize_t io61_read(io61_file* f, unsigned char* buf, size_t sz) {
    assert(f->buf_start <= f->buf_pos && f->buf_pos <= f->buf_end);
    assert(f->buf_end - f->buf_pos <= io61_file::buf_size);
    if(f->memy_buf) {
        size_t available = f->size - f->memy_off;
        size_t copysz = std::min(sz, available);
        if(copysz <= 0) {
            return -1;
        }
        memcpy(buf, f->memy_buf + f->memy_off, copysz); 
        f->memy_off += copysz;
        return copysz;
    }
    size_t position = 0;
    while (sz > position) {
        if (f->buf_pos == f->buf_end) {
            io61_fill(f); 
            if (f->buf_pos == f->buf_end) {
                break;
            }
        }
        size_t available = f->buf_end - f->buf_pos;
        size_t copysz = std::min(sz - position, available);
        memcpy(buf + position, &(f->buf[f->buf_pos - f->buf_start]), copysz);
        f->buf_pos += copysz;
        position += copysz;
    }
    return position;
}

// io61_writec(f)
//    Write a single character `c` to `f` (converted to unsigned char).
//    Returns 0 on success and -1 on error.

int io61_writec(io61_file* f, int c) {
    assert(f->buf_start <= f->buf_pos && f->buf_pos <= f->buf_end);
    assert(f->buf_end - f->buf_pos <= io61_file::buf_size); 
    unsigned char ch = c;
    if (f->buf_end == f->buf_start + io61_file::buf_size) {
        io61_flush(f);
        if (f->buf_end == f->buf_start + io61_file::buf_size) {
            return -1;
        }
    }
    f->buf[f->buf_end - f->buf_start] = ch;
    f->buf_end++;
    f->buf_pos++;
    return 0;
}

// io61_write(f, buf, sz)
//    Writes `sz` characters from `buf` to `f`. Returns `sz` on success.
//    Can write fewer than `sz` characters when there is an error, such as
//    a drive running out of space. In this case io61_write returns the
//    number of characters written, or -1 if no characters were written
//    before the error occurred.

ssize_t io61_write(io61_file* f, const unsigned char* buf, size_t sz) {
    assert(f->buf_start <= f->buf_pos && f->buf_pos <= f->buf_end);
    assert(f->buf_end - f->buf_pos <= io61_file::buf_size);
    assert(f->buf_pos == f->buf_end);
    size_t position = 0;
    while (position < sz) {
        if (f->buf_end == f->buf_start + io61_file::buf_size) {
            io61_flush(f);
            if (f->buf_end == f->buf_start + io61_file::buf_size) {
                break;
            }
        }
        size_t available = io61_file::buf_size - (f->buf_end - f->buf_start);
        size_t copysz = std::min(sz - position, available);
        memcpy(&(f->buf[f->buf_end - f->buf_start]), buf + position, copysz);
        f->buf_end += copysz;
        f->buf_pos += copysz;
        position += copysz;
    }
    return position;
}


// io61_flush(f)
//    If `f` was opened write-only, `io61_flush(f)` forces a write of any
//    cached data written to `f`. Returns 0 on success; returns -1 if an error
//    is encountered before all cached data was written.
//
//    If `f` was opened read-only, `io61_flush(f)` returns 0. It may also
//    drop any data cached for reading.

int io61_flush(io61_file* f) {
    if(f->mode == O_RDONLY) {
        return 0;
    }

    assert(f->buf_start <= f->buf_pos && f->buf_pos <= f->buf_end);
    assert(f->buf_end - f->buf_pos <= io61_file::buf_size);

    assert(f->buf_pos == f->buf_end);
    
    size_t pos = 0;
    while (pos < size_t(f->buf_end - f->buf_start)) {
        ssize_t nw = write(f->fd, f->buf + pos, f->buf_end - f->buf_start - pos); 
        if (nw >= 0) {
            pos += nw;
        } else if (nw == -1) {
            if (errno == EINTR|| errno == EAGAIN) {
                continue;
            }
            return -1;
        }
    }

    f->buf_end = f->buf_pos = f->buf_start;
    
    return 0;
}


// io61_seek(f, off)
//    Changes the file pointer for file `f` to `off` bytes into the file.
//    Returns 0 on success and -1 on failure.

int io61_seek(io61_file* f, off_t off) {
    if(f->memy_buf) {
        f->memy_off = off;
        return 0;
    }
    
    if (off >= f->buf_start && off <= f->buf_end && off != 0) {

        if(f->mode == O_RDONLY) {
            f->buf_pos = off;
            return 0;
        }
        else{
            f->buf_pos = f->buf_end = off;
            return 0;
        }
    } else {
        if (f->mode == O_RDONLY) {
            off_t off_aligned = (off / io61_file::buf_size) * io61_file::buf_size; 

            off_t r = lseek(f->fd, off_aligned, SEEK_SET);
            if (r == -1) {
                return -1;
            }

            f->buf_start = f->buf_pos = f->buf_end = off_aligned; 
            io61_fill(f);
            f->buf_pos = off;
        
        } else {
            int n = io61_flush(f);
            if (n == -1) {
                return -1;
            }
            off_t r = lseek(f->fd, off, SEEK_SET);
            if (r == -1) {
                return -1;
            }
            f->buf_start = f->buf_pos = f->buf_end = off;
        }

        return 0;
    }
}


// You shouldn't need to change these functions.

// io61_open_check(filename, mode)
//    Opens the file corresponding to `filename` and returns its io61_file.
//    If `!filename`, returns either the standard input or the
//    standard output, depending on `mode`. Exits with an error message if
//    `filename != nullptr` and the named file cannot be opened.

io61_file* io61_open_check(const char* filename, int mode) {
    int fd;
    if (filename) {
        fd = open(filename, mode, 0666);
    } else if ((mode & O_ACCMODE) == O_RDONLY) {
        fd = STDIN_FILENO;
    } else {
        fd = STDOUT_FILENO;
    }
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", filename, strerror(errno));
        exit(1);
    }
    return io61_fdopen(fd, mode & O_ACCMODE);
}


// io61_fileno(f)
//    Returns the file descriptor associated with `f`.

int io61_fileno(io61_file* f) {
    return f->fd;
}


// io61_filesize(f)
//    Returns the size of `f` in bytes. Returns -1 if `f` does not have a
//    well-defined size (for instance, if it is a pipe).

off_t io61_filesize(io61_file* f) {
    struct stat s;
    int r = fstat(f->fd, &s);
    if (r >= 0 && S_ISREG(s.st_mode)) {
        return s.st_size;
    } else {
        return -1;
    }
}