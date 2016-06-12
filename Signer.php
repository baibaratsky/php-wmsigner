<?php

namespace baibaratsky\WebMoney;

/**
 * WebMoney Signer: a native PHP implementation of the WMSigner module
 * @package baibaratsky\WebMoney
 */
class Signer
{
    const MB_ENCODING = '8bit'; // 8bit is the fastest suitable encoding for mb_* methods

    private $power;
    private $modulus;

    /**
     * @param string $wmid          Signer WMID
     * @param string $key           Full path to the key file or a string containing key
     * @param string $keyPassword   Key file password
     *
     * @throws \Exception
     */
    public function __construct($wmid, $key, $keyPassword)
    {
        if (empty($wmid)) {
            throw new \Exception('WMID not provided.');
        }

        if (strpos($key, "\0") === false) { // It’s a file path
            if (!is_file($key)) {
                throw new \Exception('Key file not found: ' . $key);
            }

            $key = file_get_contents($key);
            if ($key === false) {
                throw new \Exception('Error reading from the key file.');
            }
        }

        $keyData = unpack('vreserved/vsignFlag/a16hash/Vlength/a*buffer', $key);

        $keyBuffer = self::readKeyBuffer($keyData, $wmid, $keyPassword);

        if ($keyBuffer === false) {
            // Try one more time using only the first half of the password
            $keyPassword = mb_substr(
                    $keyPassword,
                    0,
                    floor(mb_strlen($keyPassword, self::MB_ENCODING) / 2),
                    self::MB_ENCODING
            );
            $keyBuffer = self::readKeyBuffer($keyData, $wmid, $keyPassword);

            if ($keyBuffer === false) {
                throw new \Exception('Hash check failed. Key file seems to be corrupted.');
            }
        }

        $this->initSignVariables($keyBuffer);
    }

    /**
     * Create a signature for the given data
     *
     * @param string $data
     *
     * @return string
     */
    public function sign($data)
    {
        // Make data hash (16 bytes)
        $base = hash('md4', $data, true);

        // Add 40 random bytes
        for ($i = 0; $i < 10; ++$i) {
            $base .= pack('V', mt_rand());
        }

        // Add the length of the base (56 = 16 + 40) as the first 2 bytes
        $base = pack('v', mb_strlen($base, self::MB_ENCODING)) . $base;

        // Modular exponentiation
        $dec = bcpowmod(self::reverseToDecimal($base), $this->power, $this->modulus, 0);

        // Convert to hexadecimal
        $hex = self::dec2hex($dec);

        // Fill empty bytes with zeros
        $hex = str_repeat('0', 132 - mb_strlen($hex, self::MB_ENCODING)) . $hex;

        // Reverse byte order
        $hexReversed = '';
        for ($i = 0; $i < mb_strlen($hex, self::MB_ENCODING) / 4; ++$i) {
            $hexReversed = mb_substr($hex, $i * 4, 4, self::MB_ENCODING) . $hexReversed;
        }

        return mb_strtolower($hexReversed, self::MB_ENCODING);
    }

    /**
     * Initialize the power and the modulus
     *
     * @param string $keyBuffer
     */
    private function initSignVariables($keyBuffer)
    {
        $data = unpack('Vreserved/vpowerLength', $keyBuffer);
        $data = unpack('Vreserved/vpowerLength/a' . $data['powerLength'] . 'power/vmodulusLength', $keyBuffer);
        $data = unpack('Vreserved/vpowerLength/a' . $data['powerLength'] . 'power/vmodulusLength/a'
                    . $data['modulusLength'] . 'modulus', $keyBuffer);
        $this->power = self::reverseToDecimal($data['power']);
        $this->modulus = self::reverseToDecimal($data['modulus']);
    }

    /**
     * Check and return the key buffer
     *
     * @param array $keyData
     * @param string $wmid
     * @param string $keyPassword
     *
     * @return string|false The key buffer, or false if the hash doesn't match
     */
    private static function readKeyBuffer($keyData, $wmid, $keyPassword)
    {
        $keyData['buffer'] = self::encryptKey($keyData['buffer'], $wmid, $keyPassword);

        return self::verifyHash($keyData) ? $keyData['buffer'] : false;
    }

    /**
     * Encrypt the key using the hash of the WMID and the key password
     *
     * @param string $keyBuffer
     * @param string $wmid
     * @param string $keyPassword
     *
     * @return string
     */
    private static function encryptKey($keyBuffer, $wmid, $keyPassword)
    {
        $hash = hash('md4', $wmid . $keyPassword, true);

        return self::xorStrings($keyBuffer, $hash, 6);
    }

    /**
     * XOR operation on two strings
     *
     * @param string $subject
     * @param string $modifier
     * @param int $shift
     *
     * @return string
     */
    private static function xorStrings($subject, $modifier, $shift = 0)
    {
        $modifierLength = mb_strlen($modifier, self::MB_ENCODING);
        $i = $shift;
        $j = 0;
        while ($i < mb_strlen($subject, self::MB_ENCODING)) {
            $subject[$i] = chr(ord($subject[$i]) ^ ord($modifier[$j]));
            ++$i;
            if (++$j >= $modifierLength) {
                $j = 0;
            }
        }

        return $subject;
    }

    /**
     * Verify the hash of the key
     *
     * @param array $keyData
     *
     * @return bool
     */
    private static function verifyHash($keyData)
    {
        $verificationString = pack('v', $keyData['reserved'])
            . pack('v', 0)
            . pack('V4', 0, 0, 0, 0)
            . pack('V', $keyData['length'])
            . $keyData['buffer'];
        $hash = hash('md4', $verificationString, true);

        return strcmp($hash, $keyData['hash']) == 0;
    }

    /**
     * Reverse byte order and convert binary data to decimal string
     *
     * @param string $binaryData
     *
     * @return string
     */
    private static function reverseToDecimal($binaryData)
    {
        return self::hex2dec(bin2hex(strrev($binaryData)));
    }

    /**
     * Convert a hexadecimal string to a decimal one
     *
     * @param string $hex
     *
     * @return string
     */
    private static function hex2dec($hex)
    {
        if (extension_loaded('gmp')) {
            return gmp_strval('0x' . $hex);
        }

        return self::hex2decBC($hex);
    }

    /**
     * Convert a hexadecimal string to a decimal one using BCMath
     *
     * @param string $hex
     *
     * @return string
     */
    private static function hex2decBC($hex) {
        $dec = '0';
        $len = mb_strlen($hex, self::MB_ENCODING);
        for ($i = 1; $i <= $len; $i++) {
            $dec = bcadd(
                $dec,
                bcmul(
                    strval(hexdec($hex[$i - 1])),
                    bcpow('16', strval($len - $i), 0),
                    0
                ),
                0
            );
        }
        return $dec;
    }

    /**
     * Convert a decimal string to a hexadecimal one
     *
     * @param string $dec
     *
     * @return string
     */
    private static function dec2hex($dec)
    {
        if (extension_loaded('gmp')) {
            return gmp_strval($dec, 16);
        }

        return self::dec2hexBC($dec);
    }

    /**
     * Convert a decimal string to a hexadecimal one using BCMath
     *
     * @param string $dec
     *
     * @return string
     */
    private static function dec2hexBC($dec) {
        $hex = '';

        while ($dec) {
            $modulus = bcmod($dec, '16');
            $hex = dechex($modulus) . $hex;
            $dec = bcdiv(bcsub($dec, $modulus, 0), '16', 0);
        }

        return $hex;
    }
}
