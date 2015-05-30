<?php

$header = <<<'EOF'
This file is part of the Firebase Token Generator.

This source file is subject to the license that is bundled
with this source code in the file LICENSE.
EOF;

Symfony\CS\Fixer\Contrib\HeaderCommentFixer::setHeader($header);

return Symfony\CS\Config\Config::create()
    ->level(Symfony\CS\FixerInterface::SYMFONY_LEVEL)
    ->fixers([
        'header_comment',
        'multiline_spaces_before_semicolon',
        'ordered_use',
        'phpdoc_order',
        'phpdoc_params',
        'align_double_arrow',
        'align_equals',
        'concat_with_spaces',
        'short_array_syntax',
        'strict',
    ])
    ->finder(
        Symfony\CS\Finder\DefaultFinder::create()
            ->exclude('vendor')
            ->in(__DIR__)
    )
;
