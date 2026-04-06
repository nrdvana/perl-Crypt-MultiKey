#ifndef CMK_YUBIKEY_OTP_H
#define CMK_YUBIKEY_OTP_H

/* Simulate `ykinfo` command on a file descriptor to a /dev/hidrawN device.
 * Returns a hashref of (a subset of) the fields `ykinfo` would return.
 * Returns NULL if the device is not a YubiKey or can't be queried.
 */
extern HV* cmk_yubico_otp_ykinfo(int fd);

/* Simulate `ykchalresp` command on a file descriptor to a /dev/hidrawN device.
 * The challenge should be supplied as raw bytes, not hex, and the output buffer
 * will likewise receive raw bytes.
 * Returns -1 if an unhandled error occurs.
 * Returns -2 if the user doesn't accept the request before the timeout
 */
extern int cmk_yubico_otp_ykchalresp(
   int fd,                    /* file handle to /dev/hidrawN  */
   int slot,                  /* 1 or 2 */
   int touch_timeout_ms,      /* milliseconds to wait for touch before giving up */
   SV *chal,                  /* challenge bytes to send to the YubiKey */
   secret_buffer *resp        /* response bytes received from the YubiKey */
);

#endif
