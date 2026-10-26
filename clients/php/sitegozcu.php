<?php
/**
 * Site Gözcü PHP istemcisi — tek dosya, bağımlılık yok (PHP 7.4+).
 *
 * Uygulamanızdaki güvenlik olaylarını Site Gözcü paneline imzalı olarak gönderir.
 * Secret ağda gönderilmez: her istek secret'tan türetilen anahtarla HMAC-SHA256 imzalanır.
 * Hiçbir zaman hata fırlatmaz; Site Gözcü'ye ulaşılamazsa false döner, siteniz etkilenmez.
 *
 *   require __DIR__ . '/sitegozcu.php';
 *   $gozcu = SiteGozcu::fromEnv(__DIR__ . '/.env');
 *   $gozcu->failedLogin($email);
 *
 * Bağlantı testi:  php sitegozcu.php test   (SITEGOZCU_* ortam değişkenleri ya da aynı klasördeki .env)
 */
final class SiteGozcu
{
    const VERSION = '1.0';
    const PATH = '/api/v1/events';
    const SIGNING_CONTEXT = 'sitegozcu/v1/signing';

    /** @var string */
    private $siteId;
    /** @var string ham (binary) imza anahtarı */
    private $signingKey;
    /** @var string */
    private $endpoint;
    /** @var float */
    private $timeout;
    /** @var string|null son hatanın açıklaması */
    public $lastError = null;

    public function __construct(string $siteId, string $secret, string $baseUrl, float $timeout = 2.0)
    {
        if (!preg_match('/^sg_(live|test)_pk_[A-Za-z0-9_-]{16,64}$/', $siteId)) {
            throw new InvalidArgumentException('SITEGOZCU_SITE_ID geçersiz (sg_live_pk_… ya da sg_test_pk_… olmalı)');
        }
        if (!preg_match('/^sg_(live|test)_sk_[A-Za-z0-9_-]{20,}$/', $secret)) {
            throw new InvalidArgumentException('SITEGOZCU_SECRET geçersiz (sg_live_sk_… ya da sg_test_sk_… olmalı)');
        }
        if (!preg_match('#^https?://[^/]+/?$#', $baseUrl)) {
            throw new InvalidArgumentException('SITEGOZCU_URL sadece şema ve alan adı olmalı, ör. https://panel.ornek.com');
        }
        $this->siteId = $siteId;
        $this->signingKey = self::deriveSigningKey($secret);
        $this->endpoint = rtrim($baseUrl, '/') . self::PATH;
        $this->timeout = $timeout;
    }

    /** Ortam değişkenlerinden (ya da verilen .env dosyasından) kurar. */
    public static function fromEnv(?string $envFile = null): self
    {
        $vars = [];
        if ($envFile !== null && is_readable($envFile)) {
            foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                if (preg_match('/^\s*(SITEGOZCU_[A-Z_]+)\s*=\s*"?([^"\r\n]*)"?\s*$/', $line, $m)) {
                    $vars[$m[1]] = $m[2];
                }
            }
        }
        $get = function (string $k) use ($vars): string {
            $v = getenv($k);
            if ($v === false || $v === '') {
                $v = $_ENV[$k] ?? $_SERVER[$k] ?? $vars[$k] ?? '';
            }
            return trim((string) $v);
        };
        return new self($get('SITEGOZCU_SITE_ID'), $get('SITEGOZCU_SECRET'), $get('SITEGOZCU_URL'));
    }

    // ——— Olay türleri ———

    /** Başarısız giriş denemesi. $user: denenen kullanıcı adı / e-posta. */
    public function failedLogin(?string $user = null, array $extra = []): bool
    {
        return $this->event('auth.failed', ['actor' => $user] + $extra);
    }

    /** Şüpheli istek (ör. SQL enjeksiyonu, yol geçişi, bilinen tarayıcı imzası). */
    public function suspiciousRequest(string $reason, array $extra = []): bool
    {
        return $this->event('request.suspicious', ['message' => $reason] + $extra);
    }

    /** Yetkisiz erişim denemesi. $resource: erişilmeye çalışılan sayfa / kaynak. */
    public function accessDenied(?string $resource = null, array $extra = []): bool
    {
        return $this->event('access.denied', ['path' => $resource] + $extra);
    }

    /** Uygulama hatası. Throwable verilirse sınıf, mesaj ve dosya:satır gönderilir (yığın izi gönderilmez). */
    public function appError($error, array $extra = []): bool
    {
        $message = $error instanceof Throwable
            ? get_class($error) . ': ' . $error->getMessage() . ' (' . basename($error->getFile()) . ':' . $error->getLine() . ')'
            : (string) $error;
        return $this->event('app.error', ['message' => $message] + $extra);
    }

    /** Bağlantı testi: olay yazmaz, sadece anahtarın çalıştığını doğrular ve panelde "Bağlandı" gösterir. */
    public function ping(): bool
    {
        return $this->send([]);
    }

    /**
     * Tek olay. $fields: actor, ip, path, message, severity (info|high|critical), meta (dizi), occurred_at (ISO 8601).
     * ip ve path verilmezse istekten alınır.
     */
    public function event(string $type, array $fields = []): bool
    {
        $e = ['type' => $type] + array_filter($fields, function ($v) { return $v !== null && $v !== ''; });
        if (!isset($e['ip']) && !empty($_SERVER['REMOTE_ADDR'])) {
            $e['ip'] = $_SERVER['REMOTE_ADDR'];
        }
        if (!isset($e['path']) && !empty($_SERVER['REQUEST_URI'])) {
            $e['path'] = substr((string) parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), 0, 300);
        }
        return $this->send([$e]);
    }

    /** En fazla 50 olayı tek istekte gönderir. */
    public function send(array $events): bool
    {
        $this->lastError = null;
        $body = json_encode(['events' => array_values($events), 'client' => 'php/' . self::VERSION], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($body === false) {
            $this->lastError = 'JSON oluşturulamadı';
            return false;
        }
        $ts = (string) time();
        $nonce = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');
        $headers = [
            'Content-Type: application/json',
            'X-SG-Site: ' . $this->siteId,
            'X-SG-Timestamp: ' . $ts,
            'X-SG-Nonce: ' . $nonce,
            'X-SG-Signature: v1=' . self::signature($this->signingKey, $ts, $nonce, 'POST', self::PATH, $body),
            'User-Agent: SiteGozcu-PHP/' . self::VERSION,
        ];
        try {
            [$status, $response] = $this->post($body, $headers);
        } catch (Throwable $e) {
            $this->lastError = $e->getMessage();
            return false;
        }
        if ($status === 202) {
            return true;
        }
        $decoded = json_decode((string) $response, true);
        $this->lastError = 'HTTP ' . $status . (is_array($decoded) && isset($decoded['error']) ? ': ' . $decoded['error'] : '');
        return false;
    }

    // ——— İmza (sunucuyla birebir aynı) ———

    public static function deriveSigningKey(string $secret): string
    {
        return hash_hmac('sha256', self::SIGNING_CONTEXT, $secret, true);
    }

    public static function signature(string $signingKey, string $ts, string $nonce, string $method, string $path, string $body): string
    {
        $canonical = implode("\n", ['v1', $ts, $nonce, strtoupper($method), $path, hash('sha256', $body)]);
        return hash_hmac('sha256', $canonical, $signingKey);
    }

    /** @return array{0:int,1:string} */
    private function post(string $body, array $headers): array
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($this->endpoint);
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT_MS => (int) ($this->timeout * 1000),
                CURLOPT_CONNECTTIMEOUT_MS => (int) ($this->timeout * 1000),
                CURLOPT_FOLLOWLOCATION => false,
            ]);
            $response = curl_exec($ch);
            if ($response === false) {
                $err = curl_error($ch);
                throw new RuntimeException($err !== '' ? $err : 'bağlantı kurulamadı');
            }
            return [(int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE), (string) $response];
        }
        $ctx = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $headers),
            'content' => $body,
            'timeout' => $this->timeout,
            'ignore_errors' => true,
            'follow_location' => 0,
        ]]);
        $response = @file_get_contents($this->endpoint, false, $ctx);
        if ($response === false) {
            throw new RuntimeException('bağlantı kurulamadı');
        }
        $status = 0;
        foreach ($http_response_header ?? [] as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $h, $m)) {
                $status = (int) $m[1];
            }
        }
        return [$status, $response];
    }
}

// Komut satırı: php sitegozcu.php test
if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    if (($argv[1] ?? '') !== 'test') {
        fwrite(STDERR, "Kullanım: php sitegozcu.php test\n");
        exit(2);
    }
    try {
        $gozcu = SiteGozcu::fromEnv(file_exists(__DIR__ . '/.env') ? __DIR__ . '/.env' : null);
    } catch (InvalidArgumentException $e) {
        fwrite(STDERR, 'Ayar hatası: ' . $e->getMessage() . "\n");
        exit(1);
    }
    if ($gozcu->ping()) {
        echo "Bağlantı başarılı: Site Gözcü panelinde bu varlık artık \"Bağlandı\" görünür.\n";
        exit(0);
    }
    fwrite(STDERR, 'Bağlantı başarısız: ' . $gozcu->lastError . "\n");
    exit(1);
}
