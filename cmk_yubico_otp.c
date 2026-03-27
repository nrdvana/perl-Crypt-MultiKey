#ifndef HAVE_LINUX_HIDRAW

/* Currently this implementation only supports Linux.  Any other platform has to fall back to
   the ykinfo and ykchalresp external commands */

bool cmk_yubico_otp_available() {
   return false;
}
HV *cmk_yubico_otp_ykinfo(int fd) {
   return NULL;
}
int cmk_yubico_otp_ykchalresp(int fd, int slot, int timeout_ms, secret_buffer *c, secret_buffer *r) {
   return -1;
}

#else

#include <linux/hiddev.h>
#include <sys/ioctl.h>

#ifndef HID_MAX_DESCRIPTOR_SIZE
#define HID_MAX_DESCRIPTOR_SIZE 4096
#endif

#define CMK_YUBICO_USB_VENDOR_ID 0x1050

static uint16_t yubikey_crc16(const uint8_t *buf, size_t len);
static int write_to_key(int fd, uint8_t slot, const void *payload, size_t payload_len);
static int read_response_from_key(int fd, uint8_t *buf, size_t bufsize, unsigned int expect_bytes, unsigned int *bytes_read_out);
static int get_serial_via_otp_hid(int fd, uint32_t *serial_out);

bool cmk_yubico_otp_available() {
   return true;
}

/* Simulate `ykinfo` command on a file descriptor to a /dev/hidrawN device.
 * Returns a hashref of (a subset of) the fields `ykinfo` would return.
 * Returns NULL if the device is not a YubiKey or can't be queried.
 */
HV *
cmk_yubico_otp_ykinfo(int fd) {
   struct hidraw_devinfo info;
   char name[256];
   uint32_t serial= 0;
   HV *ret;
   memset(&info, 0, sizeof(info));
   if (ioctl(fd, HIDIOCGRAWINFO, &info) < 0
      || info.vendor != CMK_YUBICO_USB_VENDOR_ID)
      return NULL;

   memset(name, 0, sizeof(name));
   if (ioctl(fd, HIDIOCGRAWNAME(sizeof(name)), name) < 0) {
      snprintf(name, sizeof(name), "<unavailable: %s>", strerror(errno));
   }
   name[sizeof(name)-1]= '\0';

   ret= newHV();
   hv_stores(ret, "vendor_id", newSViv(info.vendor));
   hv_stores(ret, "product_id", newSViv(info.product));
   hv_stores(ret, "name", newSVpv(name, 0));
   if (get_serial_via_otp_hid(fd, &serial) == 0)
      hv_stores(ret, "serial", newSViv(serial));
   return ret;
}

/* Simulate `ykchalresp` command on a file descriptor to a /dev/hidrawN device.
 * The challenge should be supplied as raw bytes, not hex, and the output buffer
 * will likewise receive raw bytes.
 * Returns -1 if an unhandled error occurs.
 * Returns -2 if the user doesn't accept the request before the timeout
 */
int
cmk_yubico_otp_ykchalresp(
   int fd,                    /* file handle to /dev/hidrawN  */
   int slot,                  /* 1 or 2 */
   int timeout_ms,            /* milliseconds before giving up */
   secret_buffer *challenge,  /* challenge bytes to send to the YubiKey */
   secret_buffer *response    /* response bytes received from the YubiKey */
) {
   return 0;
}

#define FEATURE_RPT_SIZE        8

#define SLOT_DEVICE_SERIAL      0x10
#define RESP_TIMEOUT_WAIT_FLAG  0x20
#define RESP_PENDING_FLAG       0x40
#define SLOT_WRITE_FLAG         0x80
#define DUMMY_REPORT_WRITE      0x8f

#define SERIAL_NUMBER_SIZE      4
#define SLOT_DATA_SIZE          64

struct frame_st {
    uint8_t payload[SLOT_DATA_SIZE];
    uint8_t slot;
    uint16_t crc;
    uint8_t filler[3];
} __attribute__((packed));

static int get_serial_via_otp_hid(int fd, uint32_t *serial_out) {
   uint8_t empty[1] = {0};
   uint8_t resp[FEATURE_RPT_SIZE * 2];
   unsigned int resp_len = 0;
   
   if (write_to_key(fd, SLOT_DEVICE_SERIAL, empty, 0) < 0) {
      return -1;
   }
   
   if (read_response_from_key(fd, resp, sizeof(resp), SERIAL_NUMBER_SIZE, &resp_len) < 0) {
      return -1;
   }
   
   *serial_out =
      ((uint32_t)resp[0] << 24) |
      ((uint32_t)resp[1] << 16) |
      ((uint32_t)resp[2] << 8)  |
      ((uint32_t)resp[3] << 0);
   
   return 0;
}

/* Same CRC-16 variant used by YubiKey OTP/personalization protocol */
static uint16_t yubikey_crc16(const uint8_t *buf, size_t len) {
   uint16_t crc = 0xffff;
   for (size_t i = 0; i < len; i++) {
      crc ^= buf[i];
      for (int j = 0; j < 8; j++) {
         if (crc & 1) {
            crc = (crc >> 1) ^ 0x8408;
         } else {
            crc >>= 1;
         }
      }
   }
   return crc;
}

static int hid_get_feature8(int fd, uint8_t data[FEATURE_RPT_SIZE]) {
   uint8_t buf[FEATURE_RPT_SIZE + 1];
   memset(buf, 0, sizeof(buf));   // report id 0 for unnumbered reports
   if (ioctl(fd, HIDIOCGFEATURE(sizeof(buf)), buf) < 0) {
      return -1;
   }
   memcpy(data, buf + 1, FEATURE_RPT_SIZE);
   return 0;
}

static int hid_set_feature8(int fd, const uint8_t data[FEATURE_RPT_SIZE]) {
   uint8_t buf[FEATURE_RPT_SIZE + 1];
   memset(buf, 0, sizeof(buf));   // report id 0 for unnumbered reports
   memcpy(buf + 1, data, FEATURE_RPT_SIZE);
   if (ioctl(fd, HIDIOCSFEATURE(sizeof(buf)), buf) < 0) {
      return -1;
   }
   return 0;
}

static int force_key_update(int fd) {
   uint8_t data[FEATURE_RPT_SIZE];
   memset(data, 0, sizeof(data));
   data[FEATURE_RPT_SIZE - 1] = DUMMY_REPORT_WRITE;
   return hid_set_feature8(fd, data);
}

static int wait_for_key_status(
   int fd,
   unsigned int max_time_ms,
   bool logic_and,
   uint8_t mask,
   uint8_t last_data[FEATURE_RPT_SIZE]
) {
   unsigned int sleep_ms = 1;
   unsigned int slept_ms = 0;
   uint8_t data[FEATURE_RPT_SIZE];

   while (slept_ms < max_time_ms) {
      usleep(sleep_ms * 1000);
      slept_ms += sleep_ms;
      sleep_ms *= 2;
      if (sleep_ms > 500) sleep_ms = 500;

      if (hid_get_feature8(fd, data) < 0) {
         return -1;
      }
      if (last_data) {
         memcpy(last_data, data, FEATURE_RPT_SIZE);
      }

      uint8_t status = data[FEATURE_RPT_SIZE - 1];

      if (logic_and) {
         if ((status & mask) == mask) {
             return 0;
         }
      } else {
         if ((status & mask) == 0) {
             return 0;
         }
      }

     // For serial we do not attempt touch/blocking behavior.
      if ((status & RESP_TIMEOUT_WAIT_FLAG) == RESP_TIMEOUT_WAIT_FLAG) {
         errno = EWOULDBLOCK;
         force_key_update(fd);
         return -1;
      }
   }

   errno = ETIMEDOUT;
   return -1;
}

static int write_to_key(int fd, uint8_t slot, const void *payload, size_t payload_len) {
   struct frame_st frame;
   uint8_t repbuf[FEATURE_RPT_SIZE];
   const uint8_t *ptr;
   const uint8_t *end;
   int seq = 0;
   
   if (payload_len > SLOT_DATA_SIZE) {
      errno = EMSGSIZE;
      return -1;
   }
   
   memset(&frame, 0, sizeof(frame));
   memcpy(frame.payload, payload, payload_len);
   frame.slot = slot;
   
   // Yubico source computes CRC over the 64-byte payload only.
   uint16_t crc = yubikey_crc16(frame.payload, sizeof(frame.payload));
   frame.crc = crc; // Arch/x86_64 is little-endian, matching old tool behavior
   
   ptr = (const uint8_t *)&frame;
   end = ptr + sizeof(frame);
   
   while (ptr < end) {
      int all_zeros = 1;
      int i;
      
      memset(repbuf, 0, sizeof(repbuf));
      for (i = 0; i < FEATURE_RPT_SIZE - 1; i++) {
         repbuf[i] = *ptr++;
         if (repbuf[i] != 0) {
            all_zeros = 0;
         }
      }
      
      // Same optimization as Yubico's code: skip all-zero interior chunks.
      if (all_zeros && seq > 0 && ptr < end) {
         seq++;
         continue;
      }
      
      repbuf[FEATURE_RPT_SIZE - 1] = (uint8_t)(seq | SLOT_WRITE_FLAG);
      
      if (wait_for_key_status(fd, 1150, false, SLOT_WRITE_FLAG, NULL) < 0) {
         return -1;
      }
      if (hid_set_feature8(fd, repbuf) < 0) {
         return -1;
      }
      
      seq++;
   }
   
   return 0;
}

static int read_response_from_key(
    int fd,
    uint8_t *buf,
    size_t bufsize,
    unsigned int expect_bytes,
    unsigned int *bytes_read_out
) {
   uint8_t data[FEATURE_RPT_SIZE];
   size_t bytes_read = 0;
   
   memset(buf, 0, bufsize);
   if (bytes_read_out) *bytes_read_out = 0;
   
   // Wait for first chunk with RESP_PENDING_FLAG set.
   if (wait_for_key_status(fd, 1000, true, RESP_PENDING_FLAG, data) < 0) {
      return -1;
   }
   
   if (bufsize < FEATURE_RPT_SIZE - 1) {
      errno = EMSGSIZE;
      force_key_update(fd);
      return -1;
   }
   
   memcpy(buf + bytes_read, data, FEATURE_RPT_SIZE - 1);
   bytes_read += FEATURE_RPT_SIZE - 1;
   
   while (bytes_read + FEATURE_RPT_SIZE <= bufsize) {
      memset(data, 0, sizeof(data));
      if (hid_get_feature8(fd, data) < 0) {
         return -1;
      }
   
      if (data[FEATURE_RPT_SIZE - 1] & RESP_PENDING_FLAG) {
         // lower 5 bits are response sequence number; 0 means done
         if ((data[FEATURE_RPT_SIZE - 1] & 31) == 0) {
            if (expect_bytes > 0) {
               unsigned int total = expect_bytes + 2; // include CRC
               uint16_t crc = yubikey_crc16(buf, total);
               if (crc != 0xf0b8) {
                  errno = EBADMSG;
                  return -1;
               }
            }
            force_key_update(fd);
            if (bytes_read_out) *bytes_read_out = (unsigned int)bytes_read;
            return 0;
         }
      
         memcpy(buf + bytes_read, data, FEATURE_RPT_SIZE - 1);
         bytes_read += FEATURE_RPT_SIZE - 1;
      } else {
         force_key_update(fd);
         errno = EPROTO;
         return -1;
      }
   }
   
   force_key_update(fd);
   errno = EMSGSIZE;
   return -1;
}

#endif

