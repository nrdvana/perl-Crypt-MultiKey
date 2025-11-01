package Crypt::MultiKey::Vault;

=head1 DESCRIPTION

  { uuid: "1234-5678-12-123456-1234",
    locks: [
      {
        key: $uuid, /* references a Key file by UUID */
        pubkey: "base64.....",
        nonce: "base64.....",
        gcm_tag: "base64.....",
        hkdf_salt: "base64.....",
        aes_key_enc: "base64.....",
      },
      ... /* for each key which can unlock the secret */
    ],
    data: "base64....."                      /* if secret is small */
    data: { uri: "file:secret-Example.enc" } /* if secret is large */
  }

=cut
