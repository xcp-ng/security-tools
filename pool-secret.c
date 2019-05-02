/*
 * Copyright (C) 2019  Vates SAS - benjamin.reis@vates.fr
 * Copyright (C) 2019  Vates SAS - ronan.abhamon@vates.fr
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// =============================================================================

struct {
  void *handle;

  unsigned long (*getError)();
  char *(*getErrorString)(unsigned long e, char *buf);
  int (*fipsModeSet)(int status);
  int (*randBytes)(unsigned char *buf, int num);
  int (*randLoadFile)(const char *filename, long max_bytes);
} CryptoLib;

// -----------------------------------------------------------------------------

static void *load_sym (void *handle, const char *name) {
  void *sym = dlsym(handle, name);
  if (!sym)
    fprintf(stderr, "Failed to load `%s` sym: `%s`.\n", name, dlerror());
  return sym;
}

static int open_crypto_lib (const char *path) {
  if (!(CryptoLib.handle = dlopen(path, RTLD_LAZY))) {
    fprintf(stderr, "Failed to open `%s`: `%s`.\n", path, dlerror());
    return -1;
  }

  void *handle = CryptoLib.handle;
  return (
    (CryptoLib.getError       = load_sym(handle, "ERR_get_error"))    &&
    (CryptoLib.getErrorString = load_sym(handle, "ERR_error_string")) &&
    (CryptoLib.fipsModeSet    = load_sym(handle, "FIPS_mode_set"))    &&
    (CryptoLib.randBytes      = load_sym(handle, "RAND_bytes"))       &&
    (CryptoLib.randLoadFile   = load_sym(handle, "RAND_load_file"))
  ) ? 0 : -1;
}

static void close_crypto_lib () { dlclose(CryptoLib.handle); }

// -----------------------------------------------------------------------------

static const char *crypto_get_error_str () {
  return (*CryptoLib.getErrorString)((*CryptoLib.getError)(), NULL);
}

static int crypto_initialize_rng () {
  if ((*CryptoLib.fipsModeSet)(1) != 1) {
    fprintf(stderr, "Failed to set FIPS mode: `%s`.\n", crypto_get_error_str());
    return -1;
  }

  if ((*CryptoLib.randLoadFile)("/dev/random", 32) != 32) {
    fprintf(stderr, "Failed to add rand bytes to PRNG.\n");
    return -1;
  }

  return 0;
}

// -----------------------------------------------------------------------------

static size_t format_to_hex (const char *src, size_t size, char *dest) {
  size_t i = 0;
  for (; i < size; ++i) {
    sprintf(dest, "%02x", (unsigned char)src[i]);
    dest += 2;
  }
  return i * 2;
}

static size_t generate_uuid (const char *src, char *dest) {
  const uint8_t sizes[] = { 4, 2, 2, 2 };

  char *p = dest;
  for (unsigned int i = 0; i < sizeof sizes; ++i) {
    p += format_to_hex(src, sizes[i], p);
    *p++ = '-';
    src += sizes[i];
  }
  p += format_to_hex(src, 6, p);

  return (size_t)(p - dest);
}

static int generate_pool_secret (char *dest) {
  char randBuf[16];
  unsigned int i = 0;
  goto start;
  for (; i < 3; ++i) {
    *dest++ = '/';
  start:
    if ((*CryptoLib.randBytes)((unsigned char *)randBuf, sizeof randBuf) != 1) {
      fprintf(stderr, "Failed to read random bytes: `%s`.\n", crypto_get_error_str());
      return -1;
    }

    dest += generate_uuid(randBuf, dest);
  }

  *dest = '\0';

  return 0;
}

// -----------------------------------------------------------------------------

int main (int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: pool_secret <libcrypto.so path>\n");
    return EXIT_FAILURE;
  }

  if (open_crypto_lib(argv[1]) < 0)
    return EXIT_FAILURE;

  char buf[128];
  if (crypto_initialize_rng() < 0 || generate_pool_secret(buf) < 0) {
    close_crypto_lib();
    return EXIT_FAILURE;
  }

  puts(buf);
  close_crypto_lib();

  return EXIT_SUCCESS;
}
