// File-input driver for the Bochs disk-image code (iodev/hdimage), built the way
// the Makefile builds bximage (-DBXIMAGE). Mirrors `bximage -func=info`:
// detect the image mode (or force one), open the image read-only, print the
// geometry and the MBR partition table, then read sectors at the start,
// middle and end of the disk.
//
// usage: hdimage_fuzz <mode|auto|vhdx-packed> <image file>
//
// vhdx-packed: a VHDX keeps its two headers and two region tables at the fixed
// offsets 64K/128K/192K/256K, so a valid image is at least 320 KiB, more than
// Mayhem fuzzes as one input. The packed input is the first 4 KiB of each of
// the five 64 KiB structure slots (file id, header 1, header 2, region table
// 1, region table 2) followed by everything from 0x50000 on (BAT, metadata,
// payload). The driver writes it back to that layout (zero-filled gaps) in a
// scratch file under $TMPDIR and opens that as a vhdx image. Every byte of the
// image comes from the input; nothing is patched.
//
// In BXIMAGE builds BX_PANIC/BX_FATAL call myexit() (an exit(1) on malformed
// images), which is why this is a file-input AFL target and not libFuzzer.
#ifndef BXIMAGE
#define BXIMAGE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "config.h"
#include "misc/bxcompat.h"
#include "osdep.h"
#include "misc/bswap.h"
#include "iodev/hdimage/hdimage.h"
#include "iodev/hdimage/vmware3.h"
#include "iodev/hdimage/vmware4.h"
#include "iodev/hdimage/vpc.h"
#include "iodev/hdimage/vhdx.h"
#include "iodev/hdimage/vbox.h"

int bx_interactive = 0;

static char scratch_path[4096];
static void remove_scratch(void) { if (scratch_path[0]) unlink(scratch_path); }

// Expands a packed VHDX input (see above) into a scratch file; returns its path.
static const char *unpack_vhdx(const char *path)
{
  const size_t slot = 64 * 1024, part = 4 * 1024, nslots = 5;
  FILE *in = fopen(path, "rb");
  if (in == NULL) return NULL;
  const char *tmp = getenv("TMPDIR");
  if (tmp == NULL || !*tmp) tmp = "/tmp";
  // One scratch file per fuzzer instance (the parent: AFL's fork server or
  // the fuzzer itself), truncated per input, so a crash or a timeout, which
  // skip atexit(), leaves at most one file behind instead of one per input.
  snprintf(scratch_path, sizeof(scratch_path), "%s/hdimage_fuzz_%ld.vhdx", tmp,
           (long)getppid());
  int fd = open(scratch_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) { scratch_path[0] = 0; fclose(in); return NULL; }
  atexit(remove_scratch);
  static char buf[64 * 1024];
  for (size_t i = 0; i < nslots; i++) {
    size_t n = fread(buf, 1, part, in);
    if (n > 0 && pwrite(fd, buf, n, (off_t)(i * slot)) != (ssize_t)n) break;
    if (n < part) break;
  }
  off_t off = (off_t)(nslots * slot);
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
    if (pwrite(fd, buf, n, off) != (ssize_t)n) break;
    off += n;
  }
  fclose(in);
  close(fd);
  return scratch_path;
}

void myexit(int code) { exit(code); }

// Same class selection as misc/bximage.cc init_image().
device_image_t* init_image(const char *imgmode)
{
  if (!strcmp(imgmode, "flat"))    return new flat_image_t();
  if (!strcmp(imgmode, "concat"))  return new concat_image_t();
  if (!strcmp(imgmode, "sparse"))  return new sparse_image_t();
  if (!strcmp(imgmode, "vmware3")) return new vmware3_image_t();
  if (!strcmp(imgmode, "vmware4")) return new vmware4_image_t();
  if (!strcmp(imgmode, "growing")) return new growing_image_t();
  if (!strcmp(imgmode, "vpc"))     return new vpc_image_t();
  if (!strcmp(imgmode, "vhdx"))    return new vhdx_image_t();
  if (!strcmp(imgmode, "vbox"))    return new vbox_image_t();
  return NULL;
}

static void read_at(device_image_t *img, Bit64u sector, Bit8u *buf)
{
  if (img->lseek((Bit64s)(sector * img->sect_size), SEEK_SET) < 0) return;
  img->read(buf, img->sect_size);
}

int main(int argc, char **argv)
{
  if (argc != 3) {
    fprintf(stderr, "usage: %s <mode|auto> <image>\n", argv[0]);
    return 2;
  }
  const char *mode = argv[1];
  const char *path = argv[2];
  if (!strcmp(mode, "vhdx-packed")) {
    mode = "vhdx";
    path = unpack_vhdx(path);
    if (path == NULL) {
      fprintf(stderr, "cannot unpack input\n");
      return 2;
    }
  } else if (!strcmp(mode, "auto")) {
    if (!hdimage_detect_image_mode(path, &mode)) {
      printf("disk image mode not detected\n");
      return 1;
    }
  }
  device_image_t *img = init_image(mode);
  if (img == NULL) {
    fprintf(stderr, "unsupported mode %s\n", mode);
    return 2;
  }
  if (img->open(path, O_RDONLY) < 0) {
    printf("cannot open %s image\n", mode);
    delete img;
    return 1;
  }
  printf("mode=%s\nsize=%llu\nsect_size=%u\n", mode,
         (unsigned long long)img->hd_size, img->sect_size);
  if (img->sect_size >= 512 && img->sect_size <= 4096) {
    Bit8u *buf = new Bit8u[img->sect_size];
    Bit64u nsect = img->hd_size / img->sect_size;
    read_at(img, 0, buf);
    if (buf[0x1fe] == 0x55 && buf[0x1ff] == 0xaa) {
      for (int n = 0; n < 4; n++) {
        Bit8u *p = &buf[0x1be + 16 * n];
        if (p[4]) {
          // MBR entries are not 4-byte aligned: copy before decoding
          Bit32u start, size;
          memcpy(&start, &p[8], 4);
          memcpy(&size, &p[12], 4);
          printf("part%d type=%02x start=%u size=%u\n", n + 1, p[4],
                 ReadHostDWordFromLittleEndian(&start),
                 ReadHostDWordFromLittleEndian(&size));
        }
      }
    }
    if (nsect > 0) {
      read_at(img, nsect / 2, buf);
      read_at(img, nsect - 1, buf);
      read_at(img, 1, buf);
    }
    delete[] buf;
  }
  img->close();
  delete img;
  return 0;
}
