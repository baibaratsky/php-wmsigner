<?php

namespace baibaratsky\WebMoney;

class Signer
{
    private $power;
    private $modulus;

    /**
     * Create RequestSigner object
     *
     * @param string $wmid          Signer WMID
     * @param string $keyFileName   Full path to the key file
     * @param string $keyPassword   Key file password
     *
     * @throws \Exception
     */
    public function __construct($wmid, $keyFileName, $keyPassword)
    {
        if (empty($wmid)) {
            throw new \Exception('WMID not provided.');
        }

        if (!file_exists($keyFileName)) {
            throw new \Exception('Key file not found: ' . $keyFileName);
        }

        $key = file_get_contents($keyFileName);
        if ($key === false) {
            throw new \Exception('Error reading from the key file.');
        }

        $keyData = unpack('vreserved/vsignFlag/a16hash/Vlength/a*buffer', $key);
        $keyData['buffer'] = self::encryptKey($keyData['buffer'], $wmid, $keyPassword);

        if (!self::verifyHash($keyData)) {
            throw new \Exception('Hash check failed. Key file seems to be corrupted.');
        }

        $this->initSignVariables($keyData['buffer']);
    }

    /**
     * Create signature for given data
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

        // Add length of the base as first 2 bytes
        $base = pack('v', strlen($base)) . $base;

        // Modular exponentiation
        $dec = bcpowmod(self::reverseToDecimal($base), $this->power, $this->modulus);

        // Convert result to hexadecimal
        $hex = self::dec2hex($dec);

        // Fill empty bytes with zeros
        $hex = str_repeat('0', 132 - strlen($hex)) . $hex;

        // Reverse byte order
        $hexReversed = '';
        for ($i = 0; $i < strlen($hex) / 4; ++$i) {
            $hexReversed = substr($hex, $i * 4, 4) . $hexReversed;
        }

        return strtolower($hexReversed);
    }

    /**
     * Initialize power and modulus
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
     * Encrypt key using hash of WMID and key password
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
     * XOR subject with modifier
     *
     * @param string $subject
     * @param string $modifier
     * @param int $shift
     *
     * @return string
     */
    private static function xorStrings($subject, $modifier, $shift = 0)
    {
        $modifierLength = strlen($modifier);
        $i = $shift;
        $j = 0;
        while ($i < strlen($subject)) {
            $subject[$i] = chr(ord($subject[$i]) ^ ord($modifier[$j]));
            ++$i;
            if (++$j >= $modifierLength) {
                $j = 0;
            }
        }

        return $subject;
    }

    /**
     * Verify hash of the key
     *
     * @param $keyData
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
     * Convert hexadecimal string to decimal string
     *
     * @param $hex
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
     * Convert hexadecimal string to decimal string using BCMath
     *
     * @param $hex
     *
     * @return string
     */
    private static function hex2decBC($hex) {
        if (strlen($hex) == 1) {
            return (string)hexdec($hex);
        }

        $last = substr($hex, -1);
        $rest = substr($hex, 0, -1);

        return bcadd(
                (string)hexdec($last),
                bcmul('16', self::hex2decBC($rest))
        );
    }

    /**
     * Convert decimal string to hexadecimal string
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
     * Convert decimal string to hexadecimal string using BCMath
     *
     * @param string $dec
     *
     * @return string
     */
    private static function dec2hexBC($dec) {
        $remainder = bcmod($dec, '16');
        $quotient = bcdiv(bcsub($dec, $remainder), '16');

        if ($quotient == 0) {
            return dechex($remainder);
        }

        return self::dec2hexBC($quotient) . dechex($remainder);
    }
}
