/*
 * Crypt::MultiKey Serialization Format.
 *
 * While a binary format would be the easiest to write in C, I'm storing
 * potentially critical pieces of data here, and being able to "see" a flipped
 * bit could make the difference between data recovery or data loss.
 * Also, text formats are nice to look at when you want a quick synopsis of
 * what's in your file.  To that end, I'm made this little INI-like format
 * for storing all the fields of Keys and Coffers and Vaults.
 * I did consider JSON or TOML, but string quoting is always such a hassle
 * that I decided to just roll my own.
 *
 * The rules are simple:
 *   - qr{^\[.*\]}       is a header defining the next dict
 *   - qr{^#.*}          is a comment
 *   - qr{^\w[^=]*= .*}  is a key=value attribute with UTF-8 text value
 *                       The leading space char leaves room for future extensions
 *   - qr{^ .*}          continues a line of the previous attribute
 *                       ("\n " represents "\n" in the value)
 *   - always ends with a blank line (\n\n or \r\n\r\n)
 *   - always write \n line endings, but allow \r\n in case file has become
 *     damaged by an editor or transfer protocol
 *
 * So for example:
 *     [Crypt::MultiKey::Key]
 *     class= X25519 0.005
 *     pubkey= 00112233445566778899AABBCCDDEEFF
 *     enc_privkey= 00112233445566778899AABBCCDEEFF
 *     pbkdf2_iter= 65535
 *
 */

struct cmk_serial_parse {
   secret_buffer *buf;
   size_t pos,
          header_ofs,
          header_len,
          key_ofs,
          key_len,
          value_ofs,
          value_len;
   const char *err;
};

static void cmk_serial_parse_init(struct cmk_serial_parse *parse, secret_buffer *buf) {
   memset(parse, 0, sizeof(*parse));
   parse->buf= buf;
}

// From the end of the previous match in cmk_serial_parse, find the next attribute,
// possibly updating the header if the parse crosses into a new dict.
#define PARSE_FAIL(reason) parse->err= reason, parse->pos= pos, return false
static bool is_valid_key_start_char(char c) {
   return c >= 'A' && c <= 'Z'
       || c >= 'a' && c <= 'z'
       || c >= '0' && c <= '9'
       || c == '_';
}
static bool is_valid_key_char(char c) {
   return is_valid_key_start_char(c) || c == '-' || c == ':';
}
static bool cmk_serial_parse_next(struct cmk_serial_parse *parse) {
   char *lim= parse->buf->data + parse->buf->len;
   char *pos= parse->buf->data + parse->pos;
   while (pos < lim) {
      // Is it a comment?
      if (*pos == '#') {
         // skip to next line
         while (pos < lim && *pos != '\n') pos++;
         pos++; // move past \n
      }
      // Is it a header?
      else if (*pos == '[') {
         char *start= pos+1, *end;
         while (pos < lim && *pos != '\n') pos++;
         end= pos[-1] == '\r'? pos - 2 : pos - 1;
         if (pos >= lim || *end != ']')
            PARSE_FAIL("incomplete table path");
         // have a complete header defined; mark it
         parse->header_ofs= start - parse->buf->data;
         parse->header_len= end - start;
         // and keep going until we get an attribute
      }
      // Is it a key=value ?
      else if (is_valid_key_start_char(*pos)) {
         char *key_start= pos, *eq_pos;
         while (pos < lim && is_valid_key_char(*pos)) pos++;
         if (pos >= lim || *pos != '=')
            PARSE_FAIL("expected '=' after key name");
         eq_pos= pos++;
         // expect at least 2 characters after the =, one to indicate the type, and at least a newline
         if (pos >= lim)
            PARSE_FAIL("expected value after '='");
         // If the next char is ' ', then it is normal free-form text, which can wrap to
         // additional lines with "\n "
         if (*pos == ' ') {
            do {
               pos++
               while (pos < lim && *pos != '\n') pos++;
            } while (pos+1 < lim && pos[1] == ' ');
            if (pos >= lim || *pos != '\n')
               PARSE_FAIL("invalid value syntax");
            parse->key_ofs= key_start - parse->buf->data;
            parse->key_len= eq_pos - key_start;
            parse->value_ofs= eq_pos + 1 - parse->buf->data;
            parse->value_len= pos - eq_pos - 1;
            parse->pos= ++pos; // start of next line
            return true;
         }
         else
            PARSE_FAIL("expected space after '='");
      }
      // Is it the end of file? (two adjacent newlines)
      else if (*pos == '\n' || (*pos == '\r' && pos+1 < lim && pos[1] == '\n')) {
         if (*pos == '\r') pos++;
         if (pos + 1 != lim)
            PARSE_FAIL("empty line before EOF");
         parse->pos= pos+1;
         return false;
      }
   }
   parse->err= "unexpected end of file";
   return false;
}

// Copy the value from the parse state into a buffer, removing any synatx from the value
static int cmk_serial_parse_utf8(struct cmk_serial_parse_state *parse, char *buf, size_t buflen) {
   char *dst= buf, *dst_lim= buf + buflen;
   char *src= parse->buf->data + parse->value_ofs, *src_lim= src + parse->value_len;
   if (dst >= dst_lim || src >= src_lim)
      return -1;
   // If first char is ' ', then simply copy every line, omitting the first ' ' char on each
   if (*src == ' ') {
      while (src < src_lim) {
         char *line= ++src; // skip over initial space char
         size_t len;
         while (src < src_lim && *src != '\n') {
            // Verify utf8-validity if it is a high character
            if (*src & 0x80) {
               if ((*src & 0xE0) == 0xC0) { // 2-byte sequence
                  if (src+1 >= src_lim || (src[1] & 0xC0) != 0x80)
                     return -1;
               }
               else if ((*src & 0xF0) == 0xE0) { // 3-byte sequence
                  if (src+2 >= src_lim || (src[1] & 0xC0) != 0x80 || (src[2] & 0xC0) != 0x80)
                     return -1;
               }
               else if ((*src & 0xF8) == 0xF0) { // 4-byte sequence
                  if (src+3 >= src_lim || (src[1] & 0xC0) != 0x80 || (src[2] & 0xC0) != 0x80 || (src[3] & 0xC0) != 0x80)
                     return -1;
               }
               else return -1; // invalid start byte
            }
            src++;
         }
         if (src < src_lim) src++; // if ended due to '\n', include '\n' in string
         len= src - line;
         if (len > 0) {
            if (dst + len > dst_lim)
               return -1; // dst buffer overflow
            memcpy(dst, line, len);
            dst += len;
         }
      }
   }
   else {
      return -1; // unknown format
   }
   return (int)(dst - buf);
}

// Parse hex characters into a buffer, returning the number of bytes added to
// the buffer, or returning -1 if any non-whitespace character is not a hex
// digit or it would overflow the buffer or if there was an an unpaired hex digit
static int cmk_serial_parse_hex(struct cmk_serial_parse_state *parse, char *buf, size_t buflen) {
   char *pos= parse->buf->data + parse->value_ofs;
   char *lim= pos + parse->value_len;
   int i= 0, high, low;
   while (pos < lim) {
      low= *pos++;
      if (low == ' ' || low == '\r' || low == '\n') continue;
      if (pos >= lim) return -1; // unpaired hex digit
      if (i >= buflen) return -1; // full buffer, too many digits
      high= *pos++;

      low -= '0';
      high -= '0';
      if (low >= ('a'-'0')) low -= ('a'-'0'-10);
      else if (low >= ('A'-'0')) low -= ('A'-'0'-10);
      if (high >= ('a'-'0')) high -= ('a'-'0'-10);
      else if (high >= ('A'-'0')) high -= ('A'-'0'-10);
      if ((low >> 4) || (high >> 4))
         return -1; // wasn't a hex digit
      buf[i++]= (high << 4) | low;
   }
   return i;
}

static bool cmk_serial_parse_long(struct cmk_serial_parse_state *parse, long *out) {
   // strtol operates on NUL-terminated strings, so make a copy first
   char str[32];
   int len= cmk_serial_parse_utf8(parse, str, sizeof(str)-1);
   long ret;
   char *end;
   if (len <= 0)
      return false;
   str[len]= 0;
   // now parse the NUL-terminated string with the usual conventions of 0x 0b etc.
   ret= strtol(str, &end, 0);
   if (*end)
      return false;
   *out= ret;
   return true;
}

