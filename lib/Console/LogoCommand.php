<?php

namespace Klxm\Hub\Console;

use Klxm\Hub\Logo;
use Klxm\Hub\Settings;
use rex_console_command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/** `php redaxo/bin/console klxm_hub:logo` – Logo des Anbieters (Discovery logo_uri) für den Anmelde-Link neu laden */
final class LogoCommand extends rex_console_command
{
    protected function configure(): void
    {
        $this->setDescription('Logo des Anbieters (Discovery logo_uri) für den Anmelde-Link neu laden');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = $this->getStyle($input, $output);
        $issuer = Settings::oidc()['issuer'];
        if ('' === $issuer) {
            $io->writeln('Kein Anbieter eingerichtet.');

            return 1;
        }
        $io->writeln(Logo::refresh($issuer) ? 'Logo geladen.' : 'Kein Logo (Anbieter nennt keins oder es ist ungültig).');

        return 0;
    }
}
