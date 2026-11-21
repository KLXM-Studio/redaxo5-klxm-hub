<?php

namespace Klxm\Hub\Console;

use Klxm\Hub\SelfTest;
use rex_console_command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** `php redaxo/bin/console klxm_hub:selftest` – Prüfungen ohne Netz und ohne Datenbank */
final class SelftestCommand extends rex_console_command
{
    protected function configure(): void
    {
        $this->setDescription('Prüft Status-Signatur, PKCE, OIDC-Client, ID-Token-Prüfungen und Abrufschutz von klxm_hub (ohne Netz)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getStyle($input, $output);
        $r = SelfTest::run();
        $io->writeln(sprintf('klxm_hub: %d in Ordnung%s', $r['ok'], $r['fails'] ? ', ' . \count($r['fails']) . ' Fehler' : ''));
        foreach ($r['fails'] as $f) {
            $io->writeln('  ✗ ' . $f);
        }
        if ($r['fails']) {
            $io->error('Selbsttest fehlgeschlagen.');

            return 1;
        }
        $io->success('Alles in Ordnung.');

        return 0;
    }
}
