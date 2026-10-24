<?php

return [
    'enabled' => env('SENTINELA_ENABLED', true),
    'url' => env('SENTINELA_URL', 'http://127.0.0.1:8765'),
    'api_key' => env('SENTINELA_API_KEY'),
    // monitor: só observa (header X-Sentinela-Risk); enforce: devolve 403 em block.
    'mode' => env('SENTINELA_MODE', 'monitor'),
    'app' => env('SENTINELA_APP', env('APP_NAME', 'laravel')),

    // O detector tem 300 ms para responder; passou disso, a requisição segue (fail-open).
    'timeout' => 0.3,

    // Campos que nunca saem da aplicação. Cookies nunca são enviados, nem listados aqui.
    'except_fields' => [
        'password', 'password_confirmation', '_token', 'token', 'card_number', 'cvv',
    ],

    // Rota cujo 401/422 conta como falha de login na janela por IP.
    'login_path' => env('SENTINELA_LOGIN_PATH', '/login'),
];
