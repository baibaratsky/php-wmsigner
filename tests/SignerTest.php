<?php

namespace baibaratsky\WebMoney;

// Mock extension_loaded() to test both GMP and BCMath methods
function extension_loaded($name)
{
    if ($name === 'gmp' && SignerTest::$disableGmp) {
        return false;
    }

    return \extension_loaded($name);
}

function file_get_contents($filename)
{
    if (SignerTest::$mockFileGetContents) {
        return false;
    }

    return \file_get_contents($filename);
}

class SignerTest extends \PHPUnit_Framework_TestCase
{
    const TEST_STRING = 'TEST';
    const TEST_SIGNATURE = '20d76ee3ad38c48805ddb2c9f1dc0644dd111b7bcc2c0b2c27d153195dd54e56da7330b4c1677098bcd8de3011b1d6c497d432bb845dcc9e8df8505ada8869650216';
    const ANOTHER_TEST_STRING = 'another test';

    const WMID = '405002833238';
    const KEY_FILE_NAME = '/test.kwm';
    const KEY_PASSWORD = 'FvGqPdAy8reVWw789';

    public static $disableGmp = false;
    public static $mockFileGetContents = false;

    protected function tearDown()
    {
        self::$disableGmp = false;
        self::$mockFileGetContents = false;
    }

    public function testSignBC()
    {
        self::$disableGmp = true;

        $signer = new Signer(self::WMID, __DIR__ . self::KEY_FILE_NAME, self::KEY_PASSWORD);

        $this->assertNotEquals(
                $signer->sign(self::TEST_STRING),
                $signer->sign(self::TEST_STRING)
        );

        // Seed the random generator with 0 to get a predictable signature
        mt_srand(0);
        $seededSignature = $signer->sign(self::TEST_STRING);

        $this->assertEquals(
                $seededSignature,
                self::TEST_SIGNATURE
        );

        mt_srand(0);
        $sameSeededSignature = $signer->sign(self::TEST_STRING);

        $this->assertEquals(
                $seededSignature,
                $sameSeededSignature
        );

        mt_srand(0);
        $anotherSeededSignature = $signer->sign(self::ANOTHER_TEST_STRING);

        $this->assertNotEquals(
                $seededSignature,
                $anotherSeededSignature
        );

        return $seededSignature;
    }

    /**
     * @requires extension gmp
     * @depends testSignBC
     * @param string $seededSignatureBC Signature produced with BCMath methods
     */
    public function testSignGmp($seededSignatureBC)
    {
        $signer = new Signer(self::WMID, __DIR__ . self::KEY_FILE_NAME, self::KEY_PASSWORD);

        // Seed the random generator with 0 to get a predictable signature
        mt_srand(0);
        $seededSignature = $signer->sign(self::TEST_STRING);

        $this->assertEquals(
                $seededSignature,
                $seededSignatureBC
        );

        mt_srand(0);
        $sameSeededSignature = $signer->sign(self::TEST_STRING);

        $this->assertEquals(
                $seededSignature,
                $sameSeededSignature
        );

        mt_srand(0);
        $anotherSeededSignature = $signer->sign(self::ANOTHER_TEST_STRING);

        $this->assertNotEquals(
                $seededSignature,
                $anotherSeededSignature
        );
    }

    /**
     * @depends testSignBC
     * @param string $seededSignatureNormalPassword Signature produced with normal password
     */
    public function testHalfPasswordCase($seededSignatureNormalPassword)
    {
        // A char added to check if the length of a password is odd
        $doubleLengthPassword = self::KEY_PASSWORD . self::KEY_PASSWORD . '!';

        $signer = new Signer(self::WMID, __DIR__ . self::KEY_FILE_NAME, $doubleLengthPassword);

        // Seed the random generator with 0 to get a predictable signature
        mt_srand(0);
        $seededSignatureHalfPassword = $signer->sign(self::TEST_STRING);

        $this->assertEquals(
                $seededSignatureNormalPassword,
                $seededSignatureHalfPassword
        );
    }

    /**
     * @depends testSignBC
     * @param string $seededSignatureFileKey Signature produced with a file key
     */
    public function testStringKey($seededSignatureFileKey)
    {
        $key = file_get_contents(__DIR__ . self::KEY_FILE_NAME);

        $signer = new Signer(self::WMID, $key, self::KEY_PASSWORD);

        // Seed the random generator with 0 to get a predictable signature
        mt_srand(0);
        $seededSignatureStringKey = $signer->sign(self::TEST_STRING);

        $this->assertEquals(
                $seededSignatureFileKey,
                $seededSignatureStringKey
        );
    }

    public function testWmidException()
    {
        $this->setExpectedException('\Exception', 'WMID not provided.');
        new Signer('', '', '');
    }

    public function testKeyFileNotFoundException()
    {
        $noSuchFile = 'no_such_file';
        $this->setExpectedException('\Exception', 'Key file not found: ' . $noSuchFile);
        new Signer('WMID', $noSuchFile, '');
    }

    public function testKeyFileReadingException()
    {
        self::$mockFileGetContents = true;
        $this->setExpectedException('\Exception', 'Error reading from the key file.');
        new Signer(self::WMID, __DIR__ . self::KEY_FILE_NAME, self::KEY_PASSWORD);
    }

    public function testKeyFileCorruptedException()
    {
        $this->setExpectedException('\Exception', 'Hash check failed. Key file seems to be corrupted.');
        new Signer(self::WMID, __DIR__ . self::KEY_FILE_NAME, '');
    }
}
