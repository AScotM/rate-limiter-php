<?php
declare(strict_types=1);

final class RateLimiter
{
    private float $rate;
    private float $capacity;
    private float $tokens;
    private float $lastRefill;
    private float $createdAt;
    private array $stats;
    private ?string $stateFile;
    private float $pollInterval;

    public function __construct(float $ratePerSecond, float $capacity, ?string $stateFile = null, float $pollInterval = 0.02)
    {
        self::positiveFinite($ratePerSecond, 'Rate');
        self::positiveFinite($capacity, 'Capacity');
        self::positiveFinite($pollInterval, 'Poll interval');
        if ($stateFile !== null && trim($stateFile) === '') {
            throw new InvalidArgumentException('State file cannot be empty');
        }
        $this->rate = $ratePerSecond;
        $this->capacity = $capacity;
        $this->tokens = $capacity;
        $this->lastRefill = microtime(true);
        $this->createdAt = $this->lastRefill;
        $this->stateFile = $stateFile;
        $this->pollInterval = $pollInterval;
        $this->stats = self::emptyStats();
        if ($stateFile !== null) {
            $this->transaction(static function (array &$state): void {});
        }
    }

    private static function emptyStats(): array
    {
        return [
            'total_checks' => 0,
            'total_grants' => 0,
            'total_denied' => 0,
            'total_wait_loops' => 0,
            'total_timeouts' => 0,
            'total_cancellations' => 0,
            'total_wait_successes' => 0,
            'total_tokens_consumed' => 0.0,
        ];
    }

    private static function positiveFinite(float $value, string $name): void
    {
        if (!is_finite($value) || $value <= 0.0) {
            throw new InvalidArgumentException("$name must be finite and positive");
        }
    }

    private function validateCount(float $count): float
    {
        self::positiveFinite($count, 'Count');
        if ($count > $this->capacity) {
            throw new InvalidArgumentException('Requested count exceeds bucket capacity');
        }
        return $count;
    }

    private static function validateTimeout(?float $timeout): void
    {
        if ($timeout !== null && (!is_finite($timeout) || $timeout < 0.0)) {
            throw new InvalidArgumentException('Timeout must be finite and nonnegative');
        }
    }

    private function defaultState(): array
    {
        return [
            'rate' => $this->rate,
            'capacity' => $this->capacity,
            'tokens' => $this->capacity,
            'last_refill' => microtime(true),
            'created_at' => microtime(true),
            'stats' => self::emptyStats(),
        ];
    }

    private function refill(array &$state): void
    {
        $now = microtime(true);
        $elapsed = max(0.0, $now - (float) $state['last_refill']);
        $state['tokens'] = min((float) $state['capacity'], max(0.0, (float) $state['tokens'] + $elapsed * (float) $state['rate']));
        $state['last_refill'] = $now;
    }

    private function transaction(callable $callback): mixed
    {
        if ($this->stateFile === null) {
            $state = [
                'rate' => $this->rate,
                'capacity' => $this->capacity,
                'tokens' => $this->tokens,
                'last_refill' => $this->lastRefill,
                'created_at' => $this->createdAt,
                'stats' => $this->stats,
            ];
            $this->refill($state);
            try {
                return $callback($state);
            } finally {
                $this->rate = (float) $state['rate'];
                $this->capacity = (float) $state['capacity'];
                $this->tokens = (float) $state['tokens'];
                $this->lastRefill = (float) $state['last_refill'];
                $this->createdAt = (float) $state['created_at'];
                $this->stats = $state['stats'];
            }
        }

        $handle = @fopen($this->stateFile, 'c+');
        if ($handle === false) {
            throw new RuntimeException('Cannot open shared state file');
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Cannot lock shared state file');
            }
            try {
                rewind($handle);
                $raw = stream_get_contents($handle);
                if ($raw === false) {
                    throw new RuntimeException('Cannot read shared state');
                }
                if (trim($raw) === '') {
                    $state = $this->defaultState();
                } else {
                    $state = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
                    if (!is_array($state) || !isset($state['rate'], $state['capacity'], $state['tokens'], $state['last_refill'], $state['created_at'], $state['stats']) || !is_array($state['stats'])) {
                        throw new RuntimeException('Invalid shared state structure');
                    }
                    foreach (['rate', 'capacity', 'tokens', 'last_refill', 'created_at'] as $key) {
                        if (!is_numeric($state[$key]) || !is_finite((float) $state[$key])) {
                            throw new RuntimeException('Invalid shared state value');
                        }
                    }
                    self::positiveFinite((float) $state['rate'], 'Stored rate');
                    self::positiveFinite((float) $state['capacity'], 'Stored capacity');
                    $state['stats'] = array_replace(self::emptyStats(), $state['stats']);
                }
                $this->refill($state);
                $this->rate = (float) $state['rate'];
                $this->capacity = (float) $state['capacity'];
                $result = $callback($state);
                $encoded = json_encode($state, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION);
                rewind($handle);
                if (!ftruncate($handle, 0)) {
                    throw new RuntimeException('Cannot truncate shared state');
                }
                $length = strlen($encoded);
                $written = 0;
                while ($written < $length) {
                    $n = fwrite($handle, substr($encoded, $written));
                    if ($n === false || $n === 0) {
                        throw new RuntimeException('Cannot write shared state');
                    }
                    $written += $n;
                }
                fflush($handle);
                return $result;
            } finally {
                flock($handle, LOCK_UN);
            }
        } finally {
            fclose($handle);
        }
    }

    public function consume(float $count = 1.0): bool
    {
        $this->validateCount($count);
        return $this->transaction(static function (array &$state) use ($count): bool {
            $state['stats']['total_checks']++;
            if ($state['tokens'] + 1e-12 >= $count) {
                $state['tokens'] = max(0.0, $state['tokens'] - $count);
                $state['stats']['total_grants']++;
                $state['stats']['total_tokens_consumed'] += $count;
                return true;
            }
            $state['stats']['total_denied']++;
            return false;
        });
    }

    public function allowRequest(): bool
    {
        return $this->consume();
    }

    public function allowRequests(float $count): bool
    {
        return $this->consume($count);
    }

    public function getWaitTime(float $count = 1.0): float
    {
        $this->validateCount($count);
        return $this->transaction(static function (array &$state) use ($count): float {
            return max(0.0, ($count - $state['tokens']) / $state['rate']);
        });
    }

    public function waitForTokens(float $count = 1.0, ?float $maxWaitSeconds = null, ?callable $cancelled = null): bool
    {
        $this->validateCount($count);
        self::validateTimeout($maxWaitSeconds);
        $start = hrtime(true) / 1e9;
        $waited = false;
        while (true) {
            if ($cancelled !== null && $cancelled()) {
                $this->transaction(static function (array &$state): void {
                    $state['stats']['total_cancellations']++;
                });
                return false;
            }
            $outcome = $this->transaction(static function (array &$state) use ($count, $waited): array {
                $state['stats']['total_checks']++;
                if ($state['tokens'] + 1e-12 >= $count) {
                    $state['tokens'] = max(0.0, $state['tokens'] - $count);
                    $state['stats']['total_grants']++;
                    $state['stats']['total_tokens_consumed'] += $count;
                    if ($waited) {
                        $state['stats']['total_wait_successes']++;
                    }
                    return [true, 0.0];
                }
                $state['stats']['total_denied']++;
                $state['stats']['total_wait_loops']++;
                return [false, max(0.0, ($count - $state['tokens']) / $state['rate'])];
            });
            if ($outcome[0]) {
                return true;
            }
            $waited = true;
            $elapsed = hrtime(true) / 1e9 - $start;
            if ($maxWaitSeconds !== null && $elapsed >= $maxWaitSeconds) {
                $this->transaction(static function (array &$state): void {
                    $state['stats']['total_timeouts']++;
                });
                return false;
            }
            $sleep = min($this->pollInterval, max(0.0001, $outcome[1]));
            if ($maxWaitSeconds !== null) {
                $sleep = min($sleep, max(0.0, $maxWaitSeconds - $elapsed));
            }
            if ($sleep > 0.0) {
                usleep((int) max(1, min(1000000, ceil($sleep * 1000000))));
            }
        }
    }

    public function waitAndConsume(float $count = 1.0): void
    {
        $this->waitForTokens($count);
    }

    public function getAvailableTokens(): float
    {
        return $this->transaction(static fn (array &$state): float => (float) $state['tokens']);
    }

    public function getAvailableTokensInt(): int
    {
        return (int) $this->getAvailableTokens();
    }

    public function getAvailablePercentage(): float
    {
        return $this->transaction(static fn (array &$state): float => $state['tokens'] / $state['capacity']);
    }

    public function isFull(): bool
    {
        return $this->transaction(static fn (array &$state): bool => $state['tokens'] >= $state['capacity'] - 1e-9);
    }

    public function getCapacity(): float
    {
        return $this->transaction(static fn (array &$state): float => (float) $state['capacity']);
    }

    public function getRate(): float
    {
        return $this->transaction(static fn (array &$state): float => (float) $state['rate']);
    }

    public function configure(float $ratePerSecond, float $capacity): void
    {
        self::positiveFinite($ratePerSecond, 'Rate');
        self::positiveFinite($capacity, 'Capacity');
        $this->transaction(static function (array &$state) use ($ratePerSecond, $capacity): void {
            $state['rate'] = $ratePerSecond;
            $state['capacity'] = $capacity;
            $state['tokens'] = min($capacity, $state['tokens']);
        });
        $this->rate = $ratePerSecond;
        $this->capacity = $capacity;
    }

    public function reset(): void
    {
        $this->transaction(static function (array &$state): void {
            $state['tokens'] = $state['capacity'];
            $state['last_refill'] = microtime(true);
            $state['stats'] = self::emptyStats();
        });
    }

    public function getStatistics(): array
    {
        $statistics = $this->transaction(static function (array &$state): array {
            return array_merge($state['stats'], [
                'rate' => $state['rate'],
                'capacity' => $state['capacity'],
                'tokens' => $state['tokens'],
                'available_tokens_int' => (int) $state['tokens'],
                'created_at' => $state['created_at'],
                'uptime' => max(0.0, microtime(true) - $state['created_at']),
                'shared' => false,
            ]);
        });
        $statistics['shared'] = $this->stateFile !== null;
        return $statistics;
    }

    public function __toString(): string
    {
        return sprintf('RateLimiter(rate=%.3f, capacity=%.3f, tokens=%.3f)', $this->getRate(), $this->getCapacity(), $this->getAvailableTokens());
    }
}

function parseArguments(array $argv): array
{
    $options = [
        'rate' => 5.0,
        'capacity' => 10.0,
        'requests' => 15,
        'tokens' => 1.0,
        'timeout' => 0.0,
        'state' => null,
        'delay' => 0.0,
        'json' => false,
        'wait' => false,
        'reset' => false,
        'test' => false,
        'help' => false,
    ];
    $numeric = ['rate', 'capacity', 'requests', 'tokens', 'timeout', 'delay'];
    $boolean = ['json', 'wait', 'reset', 'test', 'help'];
    for ($i = 1; $i < count($argv); $i++) {
        $argument = $argv[$i];
        if (!str_starts_with($argument, '--')) {
            throw new InvalidArgumentException("Unknown argument: $argument");
        }
        $key = substr($argument, 2);
        if (in_array($key, $boolean, true)) {
            $options[$key] = true;
            continue;
        }
        if (!in_array($key, [...$numeric, 'state'], true)) {
            throw new InvalidArgumentException("Unknown option: $argument");
        }
        if (!isset($argv[$i + 1])) {
            throw new InvalidArgumentException("Missing value for $argument");
        }
        $value = $argv[++$i];
        if ($key === 'state') {
            $options[$key] = $value;
        } elseif ($key === 'requests') {
            if (!ctype_digit($value)) {
                throw new InvalidArgumentException('Requests must be a nonnegative integer');
            }
            $options[$key] = (int) $value;
        } else {
            if (!is_numeric($value)) {
                throw new InvalidArgumentException("Invalid number for $argument");
            }
            $options[$key] = (float) $value;
        }
    }
    return $options;
}

function assertTest(bool $condition, string $description): void
{
    if (!$condition) {
        throw new RuntimeException("Test failed: $description");
    }
    echo "PASS $description\n";
}

function runTests(): void
{
    $limiter = new RateLimiter(2.0, 3.0);
    assertTest($limiter->consume(3.0), 'initial burst');
    assertTest(!$limiter->consume(1.0), 'burst exhausted');
    assertTest($limiter->getWaitTime() > 0.0, 'wait estimation');
    assertTest(!$limiter->waitForTokens(1.0, 0.01), 'timeout');
    $limiter->reset();
    assertTest($limiter->isFull(), 'reset');
    $limiter->configure(10.0, 5.0);
    assertTest($limiter->getCapacity() === 5.0, 'configuration');
    assertTest(!$limiter->waitForTokens(1.0, 1.0, static fn (): bool => true), 'cancellation');
    $rejected = false;
    try {
        new RateLimiter(INF, 2.0);
    } catch (InvalidArgumentException) {
        $rejected = true;
    }
    assertTest($rejected, 'nonfinite rate rejected');
    $file = tempnam(sys_get_temp_dir(), 'rate_limiter_');
    if ($file === false) {
        throw new RuntimeException('Cannot create test state file');
    }
    try {
        $first = new RateLimiter(1.0, 2.0, $file);
        $second = new RateLimiter(1.0, 2.0, $file);
        assertTest($first->consume(2.0), 'shared consume');
        assertTest(!$second->consume(1.0), 'shared state visible');
    } finally {
        unlink($file);
    }
    echo "All tests passed\n";
}

function main(array $argv): int
{
    $options = parseArguments($argv);
    if ($options['help']) {
        echo "Usage: php main.php [--rate N] [--capacity N] [--requests N] [--tokens N] [--timeout SECONDS] [--delay SECONDS] [--state FILE] [--wait] [--reset] [--json] [--test]\n";
        return 0;
    }
    if ($options['test']) {
        runTests();
        return 0;
    }
    if ($options['requests'] < 0 || !is_finite($options['delay']) || $options['delay'] < 0.0) {
        throw new InvalidArgumentException('Requests and delay must be nonnegative');
    }
    $limiter = new RateLimiter($options['rate'], $options['capacity'], $options['state']);
    if ($options['reset']) {
        $limiter->reset();
    }
    $results = [];
    for ($i = 1; $i <= $options['requests']; $i++) {
        $started = microtime(true);
        $allowed = $options['wait']
            ? $limiter->waitForTokens($options['tokens'], $options['timeout'] > 0.0 ? $options['timeout'] : null)
            : $limiter->consume($options['tokens']);
        $results[] = [
            'request' => $i,
            'allowed' => $allowed,
            'elapsed_seconds' => round(microtime(true) - $started, 6),
            'available_tokens' => round($limiter->getAvailableTokens(), 6),
        ];
        if ($options['delay'] > 0.0 && $i < $options['requests']) {
            usleep((int) min(1000000, ceil($options['delay'] * 1000000)));
        }
    }
    $stats = $limiter->getStatistics();
    $stats['shared'] = $options['state'] !== null;
    if ($options['json']) {
        echo json_encode(['requests' => $results, 'statistics' => $stats], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
    } else {
        foreach ($results as $result) {
            printf("Request %d: %s (%.4fs, %.3f tokens)\n", $result['request'], $result['allowed'] ? 'ALLOWED' : 'DENIED', $result['elapsed_seconds'], $result['available_tokens']);
        }
        echo "\nStatistics:\n";
        foreach ($stats as $key => $value) {
            printf("  %-25s %s\n", $key, is_bool($value) ? ($value ? 'true' : 'false') : (string) $value);
        }
    }
    return 0;
}

if (realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    try {
        exit(main($argv));
    } catch (Throwable $error) {
        fwrite(STDERR, 'Error: ' . $error->getMessage() . "\n");
        exit(1);
    }
}
