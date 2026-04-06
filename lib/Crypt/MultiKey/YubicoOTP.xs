MODULE = Crypt::MultiKey                PACKAGE = Crypt::MultiKey::YubicoOTP

void
_xs_ykinfo(fd)
   int fd
   INIT:
      HV *ret;
   PPCODE:
      if ((ret= cmk_yubico_otp_ykinfo(fd)))
         XPUSHs(newRV_noinc((SV*)ret));
      else
         XSRETURN_UNDEF;

void
_xs_ykchalresp(fd, slot, timeout, challenge)
   int fd
   int slot
   NV timeout
   SV *challenge
   INIT:
      SV *secret_buffer_ref= NULL;
      secret_buffer *response= secret_buffer_new(0, &secret_buffer_ref);
   PPCODE:
      switch(cmk_yubico_otp_ykchalresp(fd, slot, (int)(timeout*1000), challenge, response)) {
      case  0: ST(0)= secret_buffer_ref; XSRETURN(1); break;
      case -1: XSRETURN(0); break;
      case -2: XSRETURN_UNDEF; break;
      default: croak("BUG");
      }

