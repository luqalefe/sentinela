# Sentinela · middleware Laravel (PHP 8.1+, Laravel 10/11+)

## Instalar
Copie os três arquivos para a aplicação mantendo os caminhos:

- `app/Http/Middleware/SentinelaGuard.php`
- `config/sentinela.php`
- `resources/views/sentinela/blocked.blade.php`

## Registrar

**Laravel 10** — `app/Http/Kernel.php`:
```php
protected $middleware = [
    // ...
    \App\Http\Middleware\SentinelaGuard::class,
];
```

**Laravel 11+** — `bootstrap/app.php`:
```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\App\Http\Middleware\SentinelaGuard::class);
})
```

Para o IP real atrás de proxy, configure os proxies confiáveis (`TrustProxies`): o middleware usa `$request->ip()`.

## .env
```
SENTINELA_ENABLED=true
SENTINELA_URL=http://127.0.0.1:8765
SENTINELA_API_KEY=<mesma chave do detector>
SENTINELA_MODE=monitor   # monitor | enforce
```

- `monitor`: nunca bloqueia; veredito flag/block vira o header `X-Sentinela-Risk`.
- `enforce`: veredito `block` devolve 403 com o `alert_id`.
- Detector fora do ar ou acima de 300 ms: a requisição passa (fail-open) e o erro vai para o log.
- Nunca enviados: cookies e os campos de `except_fields` (password, _token, token, card_number, cvv…).
- Ao final de cada resposta, o status HTTP vai para `/api/feedback` (alimenta a janela por IP).
