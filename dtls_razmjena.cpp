// 01.06.2015 mdino-mac on MacOS 10.9.4 TM and © 1983-2014 Apple Inc. All Rights Reserved and MonoDevelop- Unity
// Build arka.foi.hr :
// $ gcc dtls-test.cpp -lssl -lcrypto -fno-exceptions -o dtls-test
// $ ./dtls-test . . . .


#include <stdio.h>
#include <stdint.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

namespace {

int
min(int a, int b)
{
  return a > b ? b : a;
}

const unsigned BufferSize = 8 * 1024;

struct Buffer {
  Buffer(): position(0), limit(BufferSize) { }

  uint8_t data[BufferSize];
  unsigned position;
  unsigned limit;
};

int
remaining(Buffer* b)
{
  return b->limit - b->position;
}

void
flip(Buffer* b)
{
  b->limit = b->position;
  b->position = 0;
}

void
reset(Buffer* b)
{
  b->position = 0;
  b->limit = BufferSize;
}

uint8_t*
start(Buffer* b)
{
  return b->data + b->position;
}

struct SSLState {
  SSLState(SSL_CTX* context);

  SSL* ssl;
  BIO* io;
  Buffer* cipherInput;
  Buffer* cipherOutput;
  Buffer cipherInputBuffer;
};

int
ioCreate(BIO* io)
{
  io->shutdown = 1;
  io->init = 1;
  io->num = 0;
  io->ptr = 0;  
  return 1;
}

int
ioDestroy(BIO* io)
{
  return io ? 1 : 0;
}

int
ioRead(BIO* io, char* dst, int length)
{
  SSLState* s = static_cast<SSLState*>(io->ptr);

  if (s == 0) {
    return -1;
  }

  BIO_clear_retry_flags(io);
  if (remaining(s->cipherInput) == 0) {
    BIO_set_retry_read(io);
    return -1;
  }

  length = min(length, remaining(s->cipherInput));
  memcpy(dst, start(s->cipherInput), length);
  s->cipherInput->position += length;
  return length;
}

int
ioWrite(BIO* io, const char* src, int length)
{
  SSLState* s = static_cast<SSLState*>(io->ptr);

  if (s == 0) {
    return -1;
  }

  BIO_clear_retry_flags(io);
  if (remaining(s->cipherOutput) == 0) {
    BIO_set_retry_write(io);
    return -1;
  }

  length = min(length, remaining(s->cipherOutput));
  memcpy(start(s->cipherOutput), src, length);
  s->cipherOutput->position += length;
  return length;
}

long
ioControl(BIO* io, int command, long number, void*)
{
  SSLState* s = static_cast<SSLState*>(io->ptr);

  switch (command) {
  case BIO_CTRL_RESET:
    return 0;

  case BIO_CTRL_EOF:
    return true;

  case BIO_CTRL_GET_CLOSE:
    return io->shutdown;

  case BIO_CTRL_SET_CLOSE:
    io->shutdown = number;
    return 1;

  case BIO_CTRL_WPENDING:
    return remaining(s->cipherOutput);

  case BIO_CTRL_PENDING:
    return 0;

  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
    return 1;

  case BIO_CTRL_PUSH:
  case BIO_CTRL_POP:
  default:
    return 0;
  }
}

BIO_METHOD vtable = {
  BIO_TYPE_MEM,
  "test",
  ioWrite,
  ioRead,
  0, // puts
  0, // gets
  ioControl,
  ioCreate,
  ioDestroy,
  0  // callback_ctrl
};

SSLState::SSLState(SSL_CTX* context):
  ssl(SSL_new(context)),
  io(BIO_new(&vtable)),
  cipherInput(&cipherInputBuffer),
  cipherOutput(0)
{
  io->ptr = this;
  io->flags = BIO_FLAGS_READ | BIO_FLAGS_WRITE | BIO_FLAGS_SHOULD_RETRY;
  SSL_set_bio(ssl, io, io);
}

bool
success(int error)
{
  switch (error) {
  case SSL_ERROR_NONE:
  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_READ:
    return true;

  default:
    return false;
  }
}

// generated via openssl - dh parametar -C 1024
DH *get_dh1024()
{
  static unsigned char dh1024_p[]={
    0x8A,0x17,0x35,0xD5,0xA1,0xC7,0x69,0x4D,0x4F,0x61,0xB1,0xF6,
    0x7B,0x78,0x91,0x2A,0x08,0xC3,0xC0,0x2A,0xDB,0x59,0x21,0x2D,
    0x3F,0x78,0x84,0xF7,0x2B,0x73,0xCA,0xDC,0x35,0x3B,0xD9,0x8A,
    0x86,0xC9,0xC1,0xB3,0x6C,0xB1,0xFA,0x3A,0xC4,0x09,0x61,0x08,
    0xBE,0x78,0x46,0xBF,0xCB,0x70,0xB3,0x45,0x27,0x3F,0x4A,0x80,
    0x6B,0x37,0xA1,0x5F,0x17,0x74,0xBC,0x14,0xFB,0xC4,0x7E,0x3D,
    0xD9,0xCF,0x77,0xE6,0x8A,0x71,0x81,0xDB,0x79,0x13,0x37,0xEC,
    0xA8,0x40,0x53,0xCA,0xAA,0x7B,0xC2,0x58,0x77,0x93,0xC4,0xE4,
    0x42,0x85,0xE4,0xC5,0x4D,0x0F,0x6D,0x17,0xD9,0xDE,0xFF,0xD9,
    0x82,0xD8,0x68,0x32,0x0A,0x4E,0x51,0xA6,0xC6,0x5A,0x14,0x28,
    0xDC,0xA5,0x17,0x83,0x0A,0xC9,0x41,0xA3,
  };
  static unsigned char dh1024_g[]={
    0x02,
  };
  DH *dh;

  if ((dh=DH_new()) == NULL) return(NULL);
  dh->p=BN_bin2bn(dh1024_p,sizeof(dh1024_p),NULL);
  dh->g=BN_bin2bn(dh1024_g,sizeof(dh1024_g),NULL);
  if ((dh->p == NULL) || (dh->g == NULL))
  { DH_free(dh); return(NULL); }
  return(dh);
}

void
dump(FILE* out, uint8_t* p, unsigned length)
{
  for (unsigned i = 0; i < length; ++i) {
    fprintf(out, "%02x", p[i]);
  }
}

bool
shouldDrop(int index, char** drop, int count)
{
  for (int i = 0; i < count; ++i) {
    if (index == atoi(drop[i])) {
      return true;
    }
  }
  return false;
}

} // namespace

int
main(int argc, char** argv)
{
  if (argc < 2) {
    fprintf(stderr,
            "usage: %s <message send count> "
            "[<index of message to drop> ...]\n", argv[0]);
    return -1;
  }

  int count = atoi(argv[1]);

  SSL_library_init();
  SSL_load_error_strings();

  SSL_CTX* context = SSL_CTX_new(DTLSv1_method());
  
  SSL_CTX_set_mode
    (context,
     SSL_MODE_ENABLE_PARTIAL_WRITE
     | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  SSL_CTX_set_cipher_list(context, "ADH-AES256-SHA");

  SSL_CTX_set_tmp_dh(context, get_dh1024());

  SSLState client(context);
  SSLState server(context);

  client.cipherOutput = server.cipherInput;
  server.cipherOutput = client.cipherInput;

  // do handshake:

  int serverResult = -1;
  for (int i = 0; true; ++i) {
    if (i > 10) {
      fprintf(stderr, "too many iterations!\n");
      return -1;
    }

    int clientResult = SSL_connect(client.ssl);
    if (success(SSL_get_error(client.ssl, clientResult))) {
      flip(server.cipherInput);
      reset(client.cipherInput);

      if (clientResult == 1 and serverResult == 1) {
        break;
      }

      serverResult = SSL_accept(server.ssl);
      if (success(SSL_get_error(server.ssl, serverResult))) {
        flip(client.cipherInput);
        reset(server.cipherInput);

        if (clientResult == 1 and serverResult == 1) {
          break;
        }
      } else {
        if (ERR_peek_error()) {
          ERR_print_errors_fp(stderr);
          fflush(stderr);
        }
        fprintf(stderr, "SSL_accept error %d %d\n",
                SSL_get_error(server.ssl, serverResult),
                serverResult);
        return -1;
      }
    } else {
      fprintf(stderr, "SSL_connect error\n");
      return -1;
    }
  }

  // handshake completed successfully

  // now send as many packets as requested, dropping the ones specified

  for (int i = 0; i < count; ++i) {
    const char* message = "hello, world!\n";
    reset(server.cipherInput);
    int r = SSL_write(client.ssl, message, strlen(message));
    if (r > 0) {
      if (shouldDrop(i, argv + 2, argc - 2)) {
        fputs("drop ", stderr);
        dump(stderr, server.cipherInput->data, server.cipherInput->position);
        fputs("\n", stderr);
      } else {
        fputs("pass ", stderr);
        dump(stderr, server.cipherInput->data, server.cipherInput->position);
        fputs("\n", stderr);

        flip(server.cipherInput);

        char buffer[strlen(message)];
        int c = SSL_read(server.ssl, buffer, strlen(message));
        if (c == strlen(message) and strncmp(message, buffer, c) == 0) {
          // success!
        } else if (c <= 0) {
          fprintf(stderr, "SSL_read error\n");
          return -1;
        } else {
          fprintf(stderr, "expected \"%s\", got \"%.*s\"\n",
                  message, c, buffer);
          return -1;
        }
      }
    } else {
      fprintf(stderr, "SSL_write error %d %d\n",
              SSL_get_error(server.ssl, r), r);
      return -1;
    }
  }

  printf("success!\n");
  
  return 0;
}
