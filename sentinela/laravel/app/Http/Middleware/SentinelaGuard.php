<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

class SentinelaGuard
{
    public function handle(Request $request, Closure $next)
    {
        if (! config('sentinela.enabled')) {
            return $next($request);
        }

        $request->attributes->set('sentinela_id', (string) Str::uuid());

        try {
            $resp = Http::timeout(config('sentinela.timeout'))
                ->withHeaders(['X-Sentinela-Key' => (string) config('sentinela.api_key')])
                ->post(rtrim(config('sentinela.url'), '/').'/analyze', $this->resumo($request));
            $veredito = $resp->successful() ? $resp->json() : null;
        } catch (\Throwable $e) {
            // Detector fora ou lento: a aplicação não pode cair junto.
            Log::warning('sentinela fail-open: '.$e->getMessage());
            $veredito = null;
        }

        if (! is_array($veredito)) {
            return $next($request);
        }

        if (($veredito['verdict'] ?? null) === 'block' && config('sentinela.mode') === 'enforce') {
            return response()->view('sentinela.blocked', [
                'alertId' => $veredito['alert_id'] ?? null,
            ], 403);
        }

        $response = $next($request);

        if (in_array($veredito['verdict'] ?? null, ['flag', 'block'], true)) {
            $response->headers->set('X-Sentinela-Risk', (string) ($veredito['risk'] ?? ''));
        }

        return $response;
    }

    public function terminate(Request $request, $response): void
    {
        if (! config('sentinela.enabled') || ! $request->attributes->has('sentinela_id')) {
            return;
        }

        $status = $response->getStatusCode();
        $login = $request->is(ltrim(config('sentinela.login_path'), '/'));

        try {
            Http::timeout(config('sentinela.timeout'))
                ->withHeaders(['X-Sentinela-Key' => (string) config('sentinela.api_key')])
                ->post(rtrim(config('sentinela.url'), '/').'/api/feedback', [
                    'request_id' => $request->attributes->get('sentinela_id'),
                    'ip' => $request->ip(),
                    'path' => '/'.ltrim($request->path(), '/'),
                    'status' => $status,
                    'login_failed' => $login && in_array($status, [401, 403, 422], true),
                ]);
        } catch (\Throwable $e) {
            Log::warning('sentinela feedback falhou: '.$e->getMessage());
        }
    }

    private function resumo(Request $request): array
    {
        $params = [];
        // Query + form/JSON achatados em chave => valor; except_fields sai antes de qualquer envio.
        foreach ([$request->query(), $request->except(array_keys($request->query()))] as $fonte) {
            foreach ($this->achatar($fonte) as $k => $v) {
                $params[$k] = $v;
            }
        }
        foreach (config('sentinela.except_fields') as $campo) {
            unset($params[$campo]);
            foreach (array_keys($params) as $k) {
                if (Str::endsWith($k, '.'.$campo)) {
                    unset($params[$k]);
                }
            }
        }

        return [
            'request_id' => $request->attributes->get('sentinela_id'),
            // $request->ip() respeita TrustProxies, então é o IP real atrás de proxy confiável.
            'ip' => $request->ip(),
            'method' => $request->method(),
            'path' => '/'.ltrim($request->path(), '/'),
            'params' => (object) $params,
            'user_agent' => (string) $request->userAgent(),
            'app' => config('sentinela.app'),
            'ts' => now()->utc()->format('Y-m-d\TH:i:s\Z'),
        ];
    }

    private function achatar(array $dados, string $prefixo = ''): array
    {
        $saida = [];
        foreach ($dados as $chave => $valor) {
            $nome = $prefixo === '' ? (string) $chave : $prefixo.'.'.$chave;
            if (is_array($valor)) {
                $saida += $this->achatar($valor, $nome);
            } elseif (is_scalar($valor) || $valor === null) {
                $saida[$nome] = (string) $valor;
            }
        }

        return $saida;
    }
}
