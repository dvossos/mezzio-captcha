<?php

declare(strict_types=1);

namespace Laminas\Captcha;

use Exception;
use Laminas\Captcha\Exception\RuntimeException;
use Mezzio\Session\LazySession;

use function count;
use function is_array;
use function md5;
use function random_bytes;
use function random_int;
use function strlen;
use function strtolower;
use function substr;

/**
 * AbstractWord-based captcha adapter
 *
 * Generates random word which user should recognise
 */
abstract class AbstractWord extends AbstractAdapter
{
    // @codingStandardsIgnoreStart
    /**#@+
     * @var array Character sets
     */
    /** @var list<string> */
    public static $V  = ["a", "e", "i", "o", "u", "y"];
    /** @var list<string> */
    public static $VN = ["a", "e", "i", "o", "u", "y", "2", "3", "4", "5", "6", "7", "8", "9"];
    /** @var list<string> */
    public static $C  = ["b", "c", "d", "f", "g", "h", "j", "k", "m", "n", "p", "q", "r", "s", "t", "u", "v", "w", "x", "z"];
    /** @var list<string> */
    public static $CN = ["b", "c", "d", "f", "g", "h", "j", "k", "m", "n", "p", "q", "r", "s", "t", "u", "v", "w", "x", "z", "2", "3", "4", "5", "6", "7", "8", "9"];
    /**#@-*/
    // @codingStandardsIgnoreEnd

    /**
     * Random session ID
     *
     * @var string|null
     */
    protected $id;

    /**
     * Generated word
     *
     * @var string|null
     */
    protected $word;

    /**
     * Session
     *
     * @var SessionInterface|null
     */
    protected $session;

    /**
     * Should the numbers be used or only letters
     *
     * @var bool
     */
    protected $useNumbers = true;

    /**
     * Should both cases be used or only lowercase
     *
     * @var bool
     */
    // protected $useCase = false;


    /**#@+
     * Error codes
     */
    public const MISSING_VALUE = 'missingValue';
    public const MISSING_ID    = 'missingID';
    public const BAD_CAPTCHA   = 'badCaptcha';
    /**#@-*/

    /**
     * Error messages
     *
     * @var array<string, string>
     */
    protected $messageTemplates = [
        self::MISSING_VALUE => 'Empty captcha value',
        self::MISSING_ID    => 'Captcha ID field is missing',
        self::BAD_CAPTCHA   => 'Captcha value is wrong',
    ];

    /**
     * Length of the word to generate
     *
     * @var int
     */
    protected $wordlen = 8;

    /**
     * Retrieve word length to use when generating captcha
     *
     * @return int
     */
    public function getWordlen()
    {
        return $this->wordlen;
    }

    /**
     * Set word length of captcha
     *
     * @param int $wordlen
     * @return AbstractWord Provides a fluent interface
     */
    public function setWordlen($wordlen)
    {
        $this->wordlen = $wordlen;
        return $this;
    }

    /**
     * Retrieve captcha ID
     *
     * @return string
     */
    public function getId()
    {
        if (null === $this->id) {
            $this->id = $this->generateRandomId();
        }
        return $this->id;
    }

    /**
     * Set captcha identifier
     *
     * @param string $id
     * @return AbstractWord Provides a fluent interface
     */
    protected function setId($id)
    {
        $this->id = $id;
        return $this;
    }

    /**
     * Numbers should be included in the pattern?
     *
     * @return bool
     */
    public function getUseNumbers()
    {
        return $this->useNumbers;
    }

    /**
     * Set if numbers should be included in the pattern
     *
     * @param  bool $useNumbers numbers should be included in the pattern?
     * @return AbstractWord Provides a fluent interface
     */
    public function setUseNumbers($useNumbers)
    {
        $this->useNumbers = $useNumbers;
        return $this;
    }

    /**
     * Get session object
     *
     * @throws Exception\RuntimeException
     * @return SessionInterface
     */
    public function getSession()
    {
        if (! isset($this->session)) {
            throw new RuntimeException('Session not found');
        }
        return $this->session;
    }

    /**
     * Set session namespace object
     *
     * @return $this Provides a fluent interface
     */
    public function setSession(LazySession $session)
    {
        $this->session     = $session;

        return $this;
    }

    /**
     * Get captcha word
     *
     * @return string
     */
    public function getWord()
    {
        if (empty($this->word)) {
            $session    = $this->getSession();
            $this->word = $session->get('word');
        }
        return $this->word;
    }

    /**
     * Set captcha word
     *
     * @param  string $word
     * @return AbstractWord Provides a fluent interface
     */
    protected function setWord($word)
    {
        $session       = $this->getSession();
        $session->set('word', $word);
        $this->word    = $word;
        return $this;
    }

    /**
     * Generate new random word
     *
     * @return string
     */
    protected function generateWord()
    {
        $word       = '';
        $wordLen    = $this->getWordLen();
        $vowels     = $this->useNumbers ? static::$VN : static::$V;
        $consonants = $this->useNumbers ? static::$CN : static::$C;

        $totIndexCon = count($consonants) - 1;
        $totIndexVow = count($vowels) - 1;
        for ($i = 0; $i < $wordLen; $i += 2) {
            // generate word with mix of vowels and consonants

            $consonant = $consonants[random_int(0, $totIndexCon)];
            $vowel     = $vowels[random_int(0, $totIndexVow)];
            $word     .= $consonant . $vowel;
        }

        if (strlen($word) > $wordLen) {
            $word = substr($word, 0, $wordLen);
        }

        return $word;
    }

    /**
     * Generate new session ID and new word
     *
     * @return string session ID
     */
    public function generate()
    {
        $id = $this->generateRandomId();
        $this->setId($id);
        $word = $this->generateWord();
        $this->setWord($word);
        return $id;
    }

    /**
     * Generate a random identifier
     *
     * @return string
     */
    protected function generateRandomId()
    {
        return md5(random_bytes(32));
    }

    /**
     * Validate the word
     *
     * @see    \Laminas\Validator\ValidatorInterface::isValid()
     *
     * @param  mixed $value
     * @param  mixed $context
     * @return bool
     */
    public function isValid($value, $context = null)
    {
        if (! is_array($value)) {
            if (! is_array($context)) {
                $this->error(self::MISSING_VALUE);
                return false;
            }
            $value = $context;
        }

        $name = $this->getName();

        if (isset($value[$name])) {
            $value = $value[$name];
        }

        if (! isset($value['input'])) {
            $this->error(self::MISSING_VALUE);
            return false;
        }
        $input = strtolower($value['input']);
        $this->setValue($input);

        if (! isset($value['id'])) {
            $this->error(self::MISSING_ID);
            return false;
        }

        $this->id = $value['id'];
        if ($input !== $this->getWord()) {
            $this->error(self::BAD_CAPTCHA);
            return false;
        }

        return true;
    }

    /**
     * Get helper name used to render captcha
     *
     * @return string
     */
    public function getHelperName()
    {
        return 'captcha/word';
    }
}
