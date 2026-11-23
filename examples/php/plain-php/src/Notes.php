<?php

declare(strict_types=1);

/**
 * The application's own data: a list of notes in one JSON file.
 *
 * PHP keeps nothing in memory between requests, so the list lives in the
 * system temp directory, guarded by a file lock. A real application would
 * use a database; this has nothing to do with Keyora.
 */
final class Notes
{
    private readonly string $file;

    public function __construct(?string $file = null)
    {
        $this->file = $file ?? sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'keyora_example_notes.json';
    }

    /** @return list<array{text: string, author: string}> */
    public function all(): array
    {
        return $this->locked(LOCK_SH, fn (array $notes) => [$notes, null]);
    }

    /**
     * @param array{text: string, author: string} $note
     */
    public function add(array $note): void
    {
        $this->locked(LOCK_EX, fn (array $notes) => [null, [...$notes, $note]]);
    }

    /**
     * Runs $fn with the current notes while holding the lock. $fn returns
     * [result, notesToWrite]; a null second element leaves the file alone.
     */
    private function locked(int $mode, callable $fn): mixed
    {
        $handle = fopen($this->file, 'c+');
        if ($handle === false || !flock($handle, $mode)) {
            throw new RuntimeException("cannot open the notes file {$this->file}");
        }
        try {
            $notes = json_decode((string) stream_get_contents($handle), true);
            if (!is_array($notes)) {
                $notes = [['text' => 'Welcome to Keyora', 'author' => 'system']];
            }
            [$result, $updated] = $fn($notes);
            if ($updated !== null) {
                ftruncate($handle, 0);
                rewind($handle);
                fwrite($handle, json_encode($updated));
                fflush($handle);
            }
            return $result;
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
