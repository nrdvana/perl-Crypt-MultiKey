MODULE = Crypt::MultiKey                PACKAGE = Crypt::MultiKey::FIDO2

void
_list_devices()
   INIT:
      AV *ret;
   PPCODE:
      if (!(ret= cmk_fido2_list_devices()))
         XSRETURN_UNDEF;
      XPUSHs(sv_2mortal(newRV_noinc((SV*)ret)));

