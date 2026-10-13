<?php

namespace Drupal\thessley_passkey;

/**
 * Verifies that an enrolled key lives inside a genuine TPM 2.0 chip.
 *
 * The device proves it in three steps, all checked here with OpenSSL only:
 *  1. Its endorsement key (EK) certificate chains to a TPM manufacturer root we trust.
 *  2. Credential activation: we encrypt a random secret to that EK, bound to the name of a
 *     fresh attestation key (AK). Only a TPM that holds both the EK and the AK can recover it.
 *  3. That AK certifies (signs) the signing key's name over our enrolment nonce, and the
 *     certified attributes say the key is fixed to the chip and was generated inside it.
 *
 * What is proven: the key is non-exportable and lives in a TPM whose maker is the one named in
 * the certificate. What is not: revocation (CRLs are not checked) and the firmware's security.
 * Only ECC P-256 endorsement keys with SHA-256 names are supported.
 */
class Tpm {

  const ALG_ECC = 0x0023;
  const ALG_SHA256 = 0x000B;
  const ALG_NULL = 0x0010;
  const ALG_ECDSA = 0x0018;
  const ALG_AES = 0x0006;
  const CURVE_P256 = 0x0003;
  const MAGIC = 0xFF544347;
  const ST_CERTIFY = 0x8017;

  const ATTR_FIXEDTPM = 0x00000002;
  const ATTR_FIXEDPARENT = 0x00000010;
  const ATTR_SENSITIVEDATAORIGIN = 0x00000020;
  const ATTR_RESTRICTED = 0x00010000;
  const ATTR_DECRYPT = 0x00020000;
  const ATTR_SIGN = 0x00040000;

  // SPKI header for an uncompressed prime256v1 public key.
  const P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200";

  // ---- little parsing helpers ----------------------------------------------------------

  /** Reads $len bytes at &$off, or throws. */
  protected static function take(string $data, int &$off, int $len): string {
    if ($len < 0 || $off + $len > strlen($data)) {
      throw new \InvalidArgumentException('Truncated TPM structure.');
    }
    $out = substr($data, $off, $len);
    $off += $len;
    return $out;
  }

  protected static function u16(string $data, int &$off): int {
    return unpack('n', self::take($data, $off, 2))[1];
  }

  protected static function u32(string $data, int &$off): int {
    return unpack('N', self::take($data, $off, 4))[1];
  }

  protected static function tpm2b(string $data, int &$off): string {
    return self::take($data, $off, self::u16($data, $off));
  }

  protected static function pad32(string $bin): string {
    $bin = ltrim($bin, "\0");
    if (strlen($bin) > 32) {
      throw new \InvalidArgumentException('Value too long for P-256.');
    }
    return str_pad($bin, 32, "\0", STR_PAD_LEFT);
  }

  // ---- TPMT_PUBLIC ------------------------------------------------------------------------

  /**
   * Parses an ECC TPMT_PUBLIC (not the TPM2B wrapper).
   *
   * @return array{type:int,nameAlg:int,attributes:int,authPolicy:string,scheme:int,curve:int,x:string,y:string,raw:string}
   */
  public static function parsePublic(string $raw): array {
    $off = 0;
    $type = self::u16($raw, $off);
    $nameAlg = self::u16($raw, $off);
    $attributes = self::u32($raw, $off);
    $authPolicy = self::tpm2b($raw, $off);
    if ($type !== self::ALG_ECC || $nameAlg !== self::ALG_SHA256) {
      throw new \InvalidArgumentException('Only ECC keys named with SHA-256 are supported.');
    }
    $sym = self::u16($raw, $off);
    if ($sym !== self::ALG_NULL) {
      if ($sym !== self::ALG_AES) {
        throw new \InvalidArgumentException('Unsupported symmetric algorithm.');
      }
      self::u16($raw, $off);
      self::u16($raw, $off);
    }
    $scheme = self::u16($raw, $off);
    if ($scheme !== self::ALG_NULL) {
      self::u16($raw, $off);
    }
    $curve = self::u16($raw, $off);
    $kdf = self::u16($raw, $off);
    if ($kdf !== self::ALG_NULL) {
      self::u16($raw, $off);
    }
    $x = self::tpm2b($raw, $off);
    $y = self::tpm2b($raw, $off);
    if ($off !== strlen($raw)) {
      throw new \InvalidArgumentException('Trailing bytes after the public area.');
    }
    if ($curve !== self::CURVE_P256) {
      throw new \InvalidArgumentException('Only the P-256 curve is supported.');
    }
    return [
      'type' => $type, 'nameAlg' => $nameAlg, 'attributes' => $attributes, 'authPolicy' => $authPolicy,
      'scheme' => $scheme, 'curve' => $curve, 'x' => self::pad32($x), 'y' => self::pad32($y), 'raw' => $raw,
    ];
  }

  /** TPM object name: nameAlg || H(TPMT_PUBLIC). */
  public static function name(string $tpmtPublic): string {
    return pack('n', self::ALG_SHA256) . hash('sha256', $tpmtPublic, TRUE);
  }

  /** PEM public key from a P-256 point. */
  public static function pointToPem(string $x, string $y): string {
    $der = hex2bin(self::P256_SPKI_PREFIX) . "\x04" . self::pad32($x) . self::pad32($y);
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
  }

  /** The (x, y) of an SPKI DER P-256 key, or NULL if it is not one. */
  public static function spkiToPoint(string $spkiDer): ?array {
    $prefix = hex2bin(self::P256_SPKI_PREFIX);
    if (strlen($spkiDer) !== strlen($prefix) + 65 || strncmp($spkiDer, $prefix, strlen($prefix)) !== 0 || $spkiDer[strlen($prefix)] !== "\x04") {
      return NULL;
    }
    $point = substr($spkiDer, strlen($prefix) + 1);
    return ['x' => substr($point, 0, 32), 'y' => substr($point, 32, 32)];
  }

  // ---- 1. EK certificate chain --------------------------------------------------------------

  /**
   * Checks the EK certificate chain against the trusted roots.
   *
   * @param string[] $derCerts
   *   Leaf (the EK certificate) first, then any intermediates, as DER.
   * @param string $rootsPemFile
   *   Path to a PEM bundle of trusted TPM manufacturer roots.
   *
   * @return array{x:string,y:string,manufacturer:string,model:string}|null
   *   The EK's P-256 point and the maker named in the certificate; NULL if it does not verify.
   */
  public static function verifyEkChain(array $derCerts, string $rootsPemFile): ?array {
    if (!$derCerts || count($derCerts) > 8 || !is_file($rootsPemFile)) {
      return NULL;
    }
    $pems = [];
    foreach ($derCerts as $der) {
      if (!is_string($der) || $der === '' || strlen($der) > 8192) {
        return NULL;
      }
      $pems[] = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }
    $untrusted = NULL;
    try {
      if (count($pems) > 1) {
        $untrusted = tempnam(sys_get_temp_dir(), 'tpmchain');
        file_put_contents($untrusted, implode('', array_slice($pems, 1)));
      }
      $ok = $untrusted === NULL
        ? @openssl_x509_checkpurpose($pems[0], X509_PURPOSE_ANY, [$rootsPemFile])
        : @openssl_x509_checkpurpose($pems[0], X509_PURPOSE_ANY, [$rootsPemFile], $untrusted);
    }
    finally {
      if ($untrusted !== NULL) {
        @unlink($untrusted);
      }
    }
    if ($ok !== TRUE) {
      return NULL;
    }
    $key = @openssl_pkey_get_public($pems[0]);
    $details = $key ? openssl_pkey_get_details($key) : FALSE;
    if (!$details || ($details['type'] ?? NULL) !== OPENSSL_KEYTYPE_EC || ($details['ec']['curve_name'] ?? '') !== 'prime256v1') {
      return NULL;
    }
    $parsed = openssl_x509_parse($pems[0]);
    $san = (string) ($parsed['extensions']['subjectAltName'] ?? '');
    $eku = (string) ($parsed['extensions']['extendedKeyUsage'] ?? '');
    if ($eku !== '' && strpos($eku, '2.23.133.8.1') === FALSE && stripos($eku, 'tcg-kp-EKCertificate') === FALSE && stripos($eku, 'Endorsement Key Certificate') === FALSE) {
      return NULL;
    }
    $maker = '';
    $model = '';
    if (preg_match('/(?:2\.23\.133\.2\.1|tpmManufacturer)\s*=\s*id:([0-9A-Fa-f]{8})/', $san, $m)) {
      $maker = trim(hex2bin($m[1]), "\0 ");
    }
    if (preg_match('/(?:2\.23\.133\.2\.2|tpmModel)\s*=\s*([^\/,]+)/', $san, $m)) {
      $model = substr(trim($m[1]), 0, 32);
    }
    return [
      'x' => self::pad32($details['ec']['x']),
      'y' => self::pad32($details['ec']['y']),
      'manufacturer' => $maker,
      'model' => $model,
    ];
  }

  // ---- 2. credential activation --------------------------------------------------------------

  /** TPM2 KDFa (SP 800-108 counter mode, HMAC-SHA256), one block is enough for our sizes. */
  protected static function kdfa(string $key, string $label, string $contextU, string $contextV, int $bits): string {
    $out = '';
    $counter = 1;
    while (strlen($out) * 8 < $bits) {
      $out .= hash_hmac('sha256', pack('N', $counter) . $label . "\0" . $contextU . $contextV . pack('N', $bits), $key, TRUE);
      $counter++;
    }
    return substr($out, 0, intdiv($bits, 8));
  }

  /**
   * TPM2_MakeCredential for an ECC P-256 EK: encrypts $secret so only the TPM holding the EK and
   * a loaded object named $akName can recover it.
   *
   * @return array{credential_blob:string,secret:string}
   *   Marshalled TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET.
   */
  public static function makeCredential(string $ekX, string $ekY, string $akName, string $secret): array {
    if (strlen($secret) < 1 || strlen($secret) > 32) {
      throw new \InvalidArgumentException('Credential must be 1-32 bytes.');
    }
    $eph = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
    $details = openssl_pkey_get_details($eph);
    $qeX = self::pad32($details['ec']['x']);
    $qeY = self::pad32($details['ec']['y']);
    $peer = openssl_pkey_get_public(self::pointToPem($ekX, $ekY));
    $z = openssl_pkey_derive($peer, $eph, 32);
    if ($z === FALSE) {
      throw new \RuntimeException('ECDH failed.');
    }
    $z = self::pad32($z);
    // Seed: concatenation KDF (SP 800-56A) over SHA-256, one block.
    $seed = hash('sha256', pack('N', 1) . $z . "IDENTITY\0" . $qeX . self::pad32($ekX), TRUE);
    $symKey = self::kdfa($seed, 'STORAGE', $akName, '', 128);
    $encIdentity = openssl_encrypt(pack('n', strlen($secret)) . $secret, 'aes-128-cfb', $symKey, OPENSSL_RAW_DATA, str_repeat("\0", 16));
    $hmacKey = self::kdfa($seed, 'INTEGRITY', '', '', 256);
    $outer = hash_hmac('sha256', $encIdentity . $akName, $hmacKey, TRUE);
    $idObject = pack('n', strlen($outer)) . $outer . $encIdentity;
    return [
      'credential_blob' => pack('n', strlen($idObject)) . $idObject,
      'secret' => pack('n', 2 + 32 + 2 + 32) . pack('n', 32) . $qeX . pack('n', 32) . $qeY,
    ];
  }

  // ---- 3. certification of the signing key --------------------------------------------------------

  /** Raw (r, s) -> DER ECDSA signature. */
  protected static function ecdsaDer(string $r, string $s): string {
    $int = static function (string $v): string {
      $v = ltrim($v, "\0");
      if ($v === '' || ord($v[0]) > 0x7F) {
        $v = "\0" . $v;
      }
      return "\x02" . chr(strlen($v)) . $v;
    };
    $body = $int($r) . $int($s);
    return "\x30" . chr(strlen($body)) . $body;
  }

  /**
   * Verifies the AK's certification of the signing key.
   *
   * @param string $akPublic     TPMT_PUBLIC of the attestation key.
   * @param string $attest       TPMS_ATTEST bytes the AK signed.
   * @param string $signature    Marshalled TPMT_SIGNATURE (ECDSA / SHA-256).
   * @param string $keyPublic    TPMT_PUBLIC of the signing key that was certified.
   * @param string $nonce        What the AK had to sign in as qualifying data (the enrolment nonce).
   * @param string $submittedSpki The public key the site is being asked to store (SPKI DER).
   *
   * @return string|null NULL when everything checks out, otherwise a short reason.
   */
  public static function verifyCertification(string $akPublic, string $attest, string $signature, string $keyPublic, string $nonce, string $submittedSpki): ?string {
    try {
      $ak = self::parsePublic($akPublic);
      $key = self::parsePublic($keyPublic);
    }
    catch (\InvalidArgumentException $e) {
      return 'unparseable public area';
    }
    // The AK must be a restricted signing key fixed to the chip: otherwise it could be made to sign anything.
    $akNeed = self::ATTR_FIXEDTPM | self::ATTR_FIXEDPARENT | self::ATTR_RESTRICTED | self::ATTR_SIGN;
    if (($ak['attributes'] & $akNeed) !== $akNeed || ($ak['attributes'] & self::ATTR_DECRYPT)) {
      return 'attestation key is not a restricted, fixed signing key';
    }
    // The certified key: generated inside and tied to this TPM, and a plain signing key.
    $keyNeed = self::ATTR_FIXEDTPM | self::ATTR_FIXEDPARENT | self::ATTR_SENSITIVEDATAORIGIN | self::ATTR_SIGN;
    if (($key['attributes'] & $keyNeed) !== $keyNeed || ($key['attributes'] & (self::ATTR_RESTRICTED | self::ATTR_DECRYPT))) {
      return 'signing key is not fixed to the TPM';
    }
    $point = self::spkiToPoint($submittedSpki);
    if ($point === NULL || !hash_equals($point['x'], $key['x']) || !hash_equals($point['y'], $key['y'])) {
      return 'certified key is not the submitted key';
    }
    // The signature, by the AK.
    $off = 0;
    try {
      $alg = self::u16($signature, $off);
      $hash = self::u16($signature, $off);
      $r = self::tpm2b($signature, $off);
      $s = self::tpm2b($signature, $off);
    }
    catch (\InvalidArgumentException $e) {
      return 'unparseable signature';
    }
    if ($alg !== self::ALG_ECDSA || $hash !== self::ALG_SHA256 || $off !== strlen($signature)) {
      return 'unexpected signature algorithm';
    }
    $akKey = openssl_pkey_get_public(self::pointToPem($ak['x'], $ak['y']));
    if (openssl_verify($attest, self::ecdsaDer($r, $s), $akKey, OPENSSL_ALGO_SHA256) !== 1) {
      return 'bad certification signature';
    }
    // What was signed.
    try {
      $off = 0;
      $magic = self::u32($attest, $off);
      $type = self::u16($attest, $off);
      self::tpm2b($attest, $off);
      $extra = self::tpm2b($attest, $off);
      self::take($attest, $off, 8 + 4 + 4 + 1 + 8);
      $certified = self::tpm2b($attest, $off);
      self::tpm2b($attest, $off);
      if ($off !== strlen($attest)) {
        return 'trailing bytes in the attestation';
      }
    }
    catch (\InvalidArgumentException $e) {
      return 'unparseable attestation';
    }
    if ($magic !== self::MAGIC || $type !== self::ST_CERTIFY) {
      return 'not a TPM certification';
    }
    if (!hash_equals($nonce, $extra)) {
      return 'certification is not bound to this enrolment';
    }
    if (!hash_equals(self::name($keyPublic), $certified)) {
      return 'certified name does not match the key';
    }
    return NULL;
  }

}
