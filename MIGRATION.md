# Migração JSON para SQLite

O Root.ark agora pode usar SQLite para metadados sem apagar os JSON antigos.

## Variáveis de ambiente

```env
DB_ENABLED=true
DATABASE_URL=./data/rootark.sqlite
DB_READ_FALLBACK_JSON=true
DB_WRITE_LEGACY_JSON=false
DB_BACKUP_RETENTION=10
DB_AUTO_BACKUP_ON_START=false
```

- `DB_ENABLED=false` mantém o comportamento antigo em JSON.
- `DB_READ_FALLBACK_JSON` fica desativado por padrão. Ative-o explicitamente só depois de revisar os JSON antigos; links removidos por uma versão anterior podem não ter tombstones no SQLite e não podem ser distinguidos de links ainda não importados.
- `DB_WRITE_LEGACY_JSON=false` evita dual-write por padrão.

## Rodar migrations

```powershell
npm install
npm run db:migrate
```

Isso cria `./data/rootark.sqlite`, ativa WAL, foreign keys, busy timeout e aplica migrations pendentes.

## Migrar JSON para SQLite

```powershell
npm run db:migrate-json
```

O script:

- cria backup da pasta `./data` em `./data/backups/json-before-sqlite-*`;
- cria/aplica migrations;
- importa usuários, pastas, permissões, links, histórico, analytics, auditoria, versões e criptografia;
- roda em transação;
- usa UPSERT/UNIQUE;
- não apaga, move ou renomeia JSON antigos.

Pode rodar mais de uma vez sem duplicar dados.

## Backup do SQLite

```powershell
npm run db:backup
```

Cria uma cópia de `./data/rootark.sqlite` em `./data/backups/` e mantém os últimos 10 backups por padrão.

Para alterar retenção:

```powershell
$env:DB_BACKUP_RETENTION="20"
npm run db:backup
```

## Restaurar backup

1. Pare o servidor.
2. Copie o backup desejado para `./data/rootark.sqlite`.
3. Inicie o servidor novamente.

Exemplo:

```powershell
Copy-Item .\data\backups\rootark-2026-04-28T10-00-00-000Z.sqlite .\data\rootark.sqlite -Force
node server.js
```

## Rollback para JSON

Pare o servidor e rode com:

```powershell
$env:DB_ENABLED="false"
node server.js
```

Os JSON antigos permanecem preservados. Se `DB_WRITE_LEGACY_JSON=false`, alterações feitas enquanto SQLite estava ativo não são copiadas de volta para JSON automaticamente.

## Checklist pós-migração

- login admin
- login usuário comum
- criação, alteração de permissões e exclusão de usuário
- upload simples
- upload grande/chunkado
- aprovação e rejeição de upload
- download e preview
- criação, renomeação e exclusão de pasta
- permissão por pasta e por arquivo
- link público, expiração e limite de visualizações
- dashboard e analytics
- auditoria, filtros e exportação CSV
- WebSocket/realtime
- reiniciar servidor sem perder dados
- rodar `npm run db:migrate-json` duas vezes sem duplicar dados
