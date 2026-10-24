<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <title>Requisição bloqueada pelo Sentinela</title>
    <style>
        body { font-family: system-ui, sans-serif; background: #f7f7f8; color: #222; display: grid; place-items: center; min-height: 100vh; margin: 0; }
        main { background: #fff; padding: 2rem 2.5rem; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,.12); max-width: 28rem; }
        h1 { font-size: 1.25rem; margin-top: 0; }
        code { background: #eee; padding: .1rem .4rem; border-radius: 4px; }
    </style>
</head>
<body>
<main>
    <h1>Requisição bloqueada pelo Sentinela</h1>
    <p>Esta requisição foi classificada como ataque e não foi processada.</p>
    @if ($alertId)
        <p>Código do alerta: <code>{{ $alertId }}</code></p>
    @endif
</main>
</body>
</html>
