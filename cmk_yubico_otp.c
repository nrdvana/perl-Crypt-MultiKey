#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#include "cmk.h"

#ifndef HID_MAX_DESCRIPTOR_SIZE
#define HID_MAX_DESCRIPTOR_SIZE 4096
#endif

#define CMK_YUBICO_USB_VENDOR_ID 0x1050

/* Parsed YubiKey OTP status, matching the fields reported by `ykinfo -a` */
struct yk_status {
   uint8_t  version_major;
   uint8_t  version_minor;
   uint8_t  version_build;
   uint8_t  pgm_seq;
   uint16_t touch_level;
};
/* Bits in the low byte of touchLevel */
#define CONFIG1_VALID    0x01   /* slot 1 is programmed (fw >= 2.1) */
#define CONFIG2_VALID    0x02   /* slot 2 is programmed (fw >= 2.1) */
#define CONFIG1_TOUCH    0x04   /* slot 1 requires touch (fw >= 3.0) */
#define CONFIG2_TOUCH    0x08   /* slot 2 requires touch (fw >= 3.0) */
#define CONFIG_LED_INV   0x10   /* LED behavior is inverted           */
#define CONFIG_STATUS_MASK 0x1f

#define SLOT_CHAL_OTP1         0x20
#define SLOT_CHAL_OTP2         0x28
#define SLOT_CHAL_HMAC1        0x30
#define SLOT_CHAL_HMAC2        0x38

#define SHA1_DIGEST_SIZE       20
#define SHA1_MAX_BLOCK_SIZE    64

static uint16_t yubikey_crc16(const uint8_t *buf, size_t len);
static int write_to_key(int fd, uint8_t slot, const void *payload, size_t payload_len);
static int read_response_from_key(int fd, uint8_t *buf, size_t bufsize, size_t expect_bytes, int touch_timeout_ms);
static int get_serial_via_otp_hid(int fd, uint32_t *serial_out);
static int is_otp_interface(int fd, struct yk_status *st);
static int read_yk_status(int fd, struct yk_status *st);

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
   struct yk_status st;
   char name[256];
   uint32_t serial= 0;
   HV *ret;
   memset(&info, 0, sizeof(info));
   if (ioctl(fd, HIDIOCGRAWINFO, &info) < 0
      || info.vendor != CMK_YUBICO_USB_VENDOR_ID)
      return NULL;

   /* Yubikey exposes multiple hidraw devices.  Ignore all but OTP */
   if (!is_otp_interface(fd, &st))
     return NULL;

   memset(name, 0, sizeof(name));
   if (ioctl(fd, HIDIOCGRAWNAME(sizeof(name)), name) < 0) {
      snprintf(name, sizeof(name), "<unavailable: %s>", strerror(errno));
   }
   name[sizeof(name)-1]= '\0';

   ret= newHV();
   if (get_serial_via_otp_hid(fd, &serial) == 0)
      hv_stores(ret, "serial", newSViv(serial));
   hv_stores(ret, "version", Perl_newSVpvf(aTHX_ "%d.%d.%d",
      (int)st.version_major, (int)st.version_minor, (int)st.version_build));
   hv_stores(ret, "touch_level",          newSVuv(st.touch_level));
   hv_stores(ret, "programming_sequence", newSVuv(st.pgm_seq));
   hv_stores(ret, "slot1_status",         newSViv((st.touch_level & CONFIG1_VALID) ? 1 : 0));
   hv_stores(ret, "slot2_status",         newSViv((st.touch_level & CONFIG2_VALID) ? 1 : 0));
   hv_stores(ret, "vendor_id",            newSViv(info.vendor));
   hv_stores(ret, "product_id",           newSViv(info.product));
   hv_stores(ret, "name", newSVpv(name, 0));
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
   int touch_timeout_ms,      /* milliseconds to wait for touch before giving up */
   SV *chal,                  /* challenge bytes to send to the YubiKey */
   secret_buffer *resp        /* response bytes received from the YubiKey */
) {
   U8 cmd;
   U8 *dest;
   STRLEN chal_len;
   const U8 *chal_ptr= secret_buffer_SvPVbyte(chal, &chal_len);
   bool may_block;

   if (!chal_ptr || !chal_len || !resp) {
      errno = EINVAL;
      return -1;
   }

   if (slot == 1) {
      cmd = SLOT_CHAL_HMAC1;
   } else if (slot == 2) {
      cmd = SLOT_CHAL_HMAC2;
   } else {
      errno = EINVAL;
      return -1;
   }

   if (chal_len > SHA1_MAX_BLOCK_SIZE) {
      errno = EMSGSIZE;
      return -1;
   }

   if (write_to_key(fd, cmd, chal_ptr, chal_len) < 0)
      return -1;

   secret_buffer_alloc_at_least(resp, SHA1_DIGEST_SIZE + 8); /* 20 bytes + CRC + slack */
   if (read_response_from_key(fd, resp->data, resp->capacity, SHA1_DIGEST_SIZE, touch_timeout_ms) < 0) {
      if (errno == EWOULDBLOCK || errno == ETIMEDOUT)
         return -2;
      return -1;
   }
   secret_buffer_set_len(resp, SHA1_DIGEST_SIZE);

   return 0;
}

/*************************** USB Protocol Implementation ******************************/

#define FEATURE_RPT_SIZE        8

#define SLOT_DEVICE_SERIAL      0x10
#define RESP_TOUCH_WAIT_FLAG    0x20
#define RESP_PENDING_FLAG       0x40
#define RESP_ITEM_MASK          0x1f
#define SLOT_WRITE_FLAG         0x80
#define DUMMY_REPORT_WRITE      0x8f

#define TOUCH_WAIT              1
#define TOUCH_NOWAIT            0

#define SERIAL_NUMBER_SIZE      4
#define SLOT_DATA_SIZE          64

struct frame_st {
    uint8_t payload[SLOT_DATA_SIZE];
    uint8_t slot;
    uint16_t crc;
    uint8_t filler[3];
} __attribute__((packed));

static int get_serial_via_otp_hid(int fd, uint32_t *serial_out) {
   U8 empty[1] = {0};
   U8 resp[FEATURE_RPT_SIZE * 2];
   
   if (write_to_key(fd, SLOT_DEVICE_SERIAL, empty, 0) < 0)
      return -1;
   
   if (read_response_from_key(fd, resp, sizeof(resp), SERIAL_NUMBER_SIZE, 1000) < 0)
      return -1;
   
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

static int read_yk_status(int fd, struct yk_status *st) {
   uint8_t data[FEATURE_RPT_SIZE];

   if (hid_get_feature8(fd, data) < 0)
      return -1;

   /* Yubico's old yk_read_from_key() ignored byte 0 and copied bytes 1..6
    * into YK_STATUS. Byte 7 is the transport/status flags byte.
    */
   st->version_major = data[1];
   st->version_minor = data[2];
   st->version_build = data[3];
   st->pgm_seq       = data[4];
   st->touch_level   = (uint16_t)data[5] | ((uint16_t)data[6] << 8);

   return 0;
}

static int is_otp_interface(int fd, struct yk_status *status_out) {
   int desc_size = 0;
   struct hidraw_report_descriptor rd;

   /* Current parser state */
   uint16_t usage_page = 0;
   uint16_t usage = 0;
   uint32_t report_size = 0;
   uint32_t report_count = 0;

   /* What we actually care about */
   uint16_t top_usage_page = 0;
   uint16_t top_usage = 0;
   int have_top_app = 0;
   int saw_feature_8x8 = 0;

   if (ioctl(fd, HIDIOCGRDESCSIZE, &desc_size) < 0)
      return -1;

   if (desc_size <= 0 || desc_size > HID_MAX_DESCRIPTOR_SIZE) {
      errno = EPROTO;
      return -1;
   }

   memset(&rd, 0, sizeof(rd));
   rd.size = desc_size;
   if (ioctl(fd, HIDIOCGRDESC, &rd) < 0)
      return -1;

   for (int i = 0; i < rd.size; ) {
      uint8_t b = rd.value[i++];

      if (b == 0xFE) { /* long item */
         if (i + 1 >= rd.size) {
            errno = EPROTO;
            return -1;
         }
         int len = rd.value[i];
         i += 2 + len;
         continue;
      }

      int size_code = b & 0x03;
      int type      = (b >> 2) & 0x03;
      int tag       = (b >> 4) & 0x0F;
      int size      = (size_code == 3) ? 4 : size_code;
      uint32_t val  = 0;

      if (i + size > rd.size) {
         errno = EPROTO;
         return -1;
      }

      for (int j = 0; j < size; j++)
         val |= ((uint32_t)rd.value[i + j]) << (8 * j);
      i += size;

      if (type == 1 && tag == 0x0) {             /* Global: Usage Page */
         usage_page = (uint16_t)val;
      }
      else if (type == 2 && tag == 0x0) {        /* Local: Usage */
         usage = (uint16_t)val;
      }
      else if (type == 1 && tag == 0x7) {        /* Global: Report Size */
         report_size = val;
      }
      else if (type == 1 && tag == 0x9) {        /* Global: Report Count */
         report_count = val;
      }
      else if (type == 0 && tag == 0xA) {        /* Main: Collection */
         uint8_t coll_type = (uint8_t)val;

         /* First Application collection defines the interface identity */
         if (!have_top_app && coll_type == 0x01) {
            top_usage_page = usage_page;
            top_usage      = usage;
            have_top_app   = 1;
         }

         /* local Usage is consumed by a Main item */
         usage = 0;
      }
      else if (type == 0 && tag == 0xB) {        /* Main: Feature */
         if (report_size == 8 && report_count == 8)
            saw_feature_8x8 = 1;

         usage = 0;
      }
      else if (type == 0 && tag == 0x8) {        /* Main: Input */
         usage = 0;
      }
      else if (type == 0 && tag == 0x9) {        /* Main: Output */
         usage = 0;
      }
   }

   if (!have_top_app)
      return 0;

   /* FIDO */
   if (top_usage_page == 0xF1D0 && top_usage == 0x0001)
      return 0;

   /* OTP interface on YubiKey: keyboard app collection with 8-byte feature report */
   warn("usage_page=%d usage=%d saw_feature_8x8=%d\n", (int)top_usage_page, (int)top_usage, saw_feature_8x8);
   if (top_usage_page == 0x0001 && top_usage == 0x0006 && saw_feature_8x8) {
      struct yk_status st_tmp;
      if (read_yk_status(fd, status_out? status_out : &st_tmp) == 0)
         return 1;
      return 0;
   }

   return 0;
}

static int force_key_update(int fd) {
   uint8_t data[FEATURE_RPT_SIZE];
   memset(data, 0, sizeof(data));
   data[FEATURE_RPT_SIZE - 1] = DUMMY_REPORT_WRITE;
   return hid_set_feature8(fd, data);
}

/*
 * wait_for_key_status()
 *
 * Polls the YubiKey OTP HID status register until a desired condition on the
 * status byte is satisfied, or a timeout occurs.
 *
 * The status byte (last byte of the feature report) contains protocol flags:
 *
 *   RESP_PENDING_FLAG        - response data is available
 *   SLOT_WRITE_FLAG          - device is busy processing a write
 *   RESP_TOUCH_WAIT_FLAG     - device is waiting for user touch
 *
 * Parameters:
 *
 *   mask              - condition mask
 *   logic_goal        - if true:  wait until (status & mask) == mask
 *                       if false: wait until (status & mask) == 0
 *   max_time_ms       - maximum time to wait
 *   allow_touch_wait  - if false: return immediately if touch is required
 *                       if true:  wait for user touch
 *
 * Semantics:
 *
 *   RESP_TOUCH_WAIT_FLAG indicates the device is waiting for user presence.
 *   It is NOT a timeout condition.
 *
 *   - If allow_touch_wait == false:
 *       return EWOULDBLOCK immediately when touch is required
 *
 *   - If allow_touch_wait == true:
 *       continue polling until:
 *         - condition is satisfied, or
 *         - max_time_ms expires
 *
 * Return:
 *   0   success
 *  -1   error (errno = EWOULDBLOCK, ETIMEDOUT, etc.)
 */
static int wait_for_key_status(
   int fd,
   uint8_t mask,
   bool logic_goal,
   unsigned int max_time_ms,
   bool allow_touch_wait,
   uint8_t last_data[FEATURE_RPT_SIZE]
) {
   unsigned int sleep_ms = 1;
   unsigned int slept_ms = 0;
   bool waiting_for_touch = false;
   uint8_t data[FEATURE_RPT_SIZE];

   while (slept_ms < max_time_ms) {
      usleep(sleep_ms * 1000);
      slept_ms += sleep_ms;
      sleep_ms *= 2;
      if (sleep_ms > 500) sleep_ms = 500;

      if (hid_get_feature8(fd, data) < 0)
         return -1;

      if (last_data)
         memcpy(last_data, data, FEATURE_RPT_SIZE);

      uint8_t status = data[FEATURE_RPT_SIZE - 1];

      if (logic_goal) {
         if ((status & mask) == mask)
            return 0;
      } else {
         if ((status & mask) == 0)
            return 0;
      }

      if (status & RESP_TOUCH_WAIT_FLAG) {
         if (!allow_touch_wait) {
            errno = EWOULDBLOCK;
            force_key_update(fd);
            return -1;
         }
         waiting_for_touch = true;
         continue;
      }

      if (waiting_for_touch) {
         /* We were waiting for touch, but it ended without producing
          * the expected condition → treat as timeout/failure.
          */
         errno = ETIMEDOUT;
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
      
      if (wait_for_key_status(fd, SLOT_WRITE_FLAG, false, 1150, TOUCH_NOWAIT, NULL) < 0) {
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
    size_t expect_bytes,
    int touch_timeout_ms
) {
   uint8_t data[FEATURE_RPT_SIZE];
   size_t bytes_read = 0;
   int timeout= touch_timeout_ms? touch_timeout_ms : 1000;
   
   memset(buf, 0, bufsize);
   
   // Wait for first chunk with RESP_PENDING_FLAG set.
   if (wait_for_key_status(fd, RESP_PENDING_FLAG, true, timeout, touch_timeout_ms > 0, data) < 0) {
      warn("wait_for_key_status < 0");
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
      U8 status_byte;
      memset(data, 0, sizeof(data));
      if (hid_get_feature8(fd, data) < 0)
         return -1;
      status_byte= data[FEATURE_RPT_SIZE - 1];
      warn("RESP write=%d pending=%d touchwait=%d seq=%u\n",
         status_byte & SLOT_WRITE_FLAG,
         status_byte & RESP_PENDING_FLAG,
         status_byte & RESP_TOUCH_WAIT_FLAG,
         status_byte & RESP_ITEM_MASK);

      if (status_byte & RESP_PENDING_FLAG) {
         if ((status_byte & RESP_ITEM_MASK) == 0) {
            if (expect_bytes > 0) {
               unsigned int total = expect_bytes + 2; /* include CRC */

               if (bytes_read < total) {
                   errno = EPROTO;  /* or EBADMSG, but EPROTO is more accurate */
                   force_key_update(fd);
                   return -1;
               }
               if (yubikey_crc16(buf, total) != 0xf0b8) {
                  errno = EBADMSG;
                  force_key_update(fd);
                  return -1;
               }
            }
            force_key_update(fd);
            return 0;
         }

         memcpy(buf + bytes_read, data, FEATURE_RPT_SIZE - 1);
         bytes_read += FEATURE_RPT_SIZE - 1;
      } else if ((status_byte & RESP_TOUCH_WAIT_FLAG) == RESP_TOUCH_WAIT_FLAG) {
         if (!touch_timeout_ms) {
            force_key_update(fd);
            errno = EWOULDBLOCK;
            return -1;
         }
         /* still waiting for touch; poll again */
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
