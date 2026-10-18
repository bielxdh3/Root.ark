# Root.ark Sync MVP

Cliente desktop/CLI minimo para enviar arquivos novos ou alterados de uma pasta local para o Root.ark.

## Comandos

```powershell
npm run sync:init
npm run sync:start
```

`sync:init` pede URL do servidor, usuario, senha, pasta local e `folderId` de destino. A senha e usada apenas para login e nao e salva. O arquivo `.rootark-sync.json` guarda URL, usuario, token, pasta local e destino.

`sync:start` monitora a pasta local, ignora arquivos sensiveis/temporarios e envia arquivos novos ou alterados para `/upload`.

## Opcoes

```powershell
npm run sync:init -- --server http://localhost:3000 --username bielx --folder C:\RootArkSync --folder-id root
npm run sync:start -- --once
npm run sync:start -- --auto-approve true
```

Use `ROOTARK_SYNC_PASSWORD` para renovar token expirado sem salvar senha:

```powershell
$env:ROOTARK_SYNC_PASSWORD="sua-senha"
npm run sync:start
```

## Estado local

O estado fica na pasta sincronizada:

```text
.rootark-sync-state.json
```

Ele registra caminho relativo, tamanho, `mtime`, hash SHA-256, status do ultimo upload e nome remoto.

## Ignorados por padrao

- `node_modules/`
- `.git/`
- `.env`
- `*.key`
- `*.pem`
- `*.tmp`
- `*.part`
- `*.crdownload`
- `*.log`
- `~$*`
- `.rootark-sync*`
- `.rootark-sync-state.json`

## Conflitos e versoes

O MVP nao sobrescreve arquivos localmente nem apaga nada. Se o arquivo ja existe no Root.ark, o cliente envia com o mesmo nome e adiciona `versionComment`; o backend atual cria nova versao quando o arquivo e aprovado.

Por padrao o arquivo fica pendente, respeitando o fluxo atual do Root.ark. Para testes/admin, `--auto-approve true` chama a rota existente `/approve/:name` apos o upload.

## Limitacoes

- Somente local para Root.ark.
- Nao baixa arquivos remotos.
- Nao sincroniza delecoes.
- Nao suporta arquivos acima de 8 MB neste MVP, porque usa a rota simples `/upload`.
- Nao e um servico de background/startup.

## Phase 12: protocolo bidirecional protegido

O modulo `sync-client/rootark-sync-protocol.js` define a versao 2 do protocolo
client-side. Objetos usam `objectId`, `fileId` e `versionId` estaveis; revisoes
sao ordenadas por Lamport (`counter` + `deviceId`) e nao por relogio de parede.
Operacoes suportadas sao `create`, `update`, `move` e `delete` (tombstone), com
`baseRevision` para detectar conflito e rejeicao de replay/stale update no
endpoint do servidor.

Create/update usam AES-256-GCM com uma chave de arquivo de 32 bytes fornecida
pelo cliente. O AAD vincula protocolo, IDs, operacao, revisao, epoch,
compartment e device. Chaves nunca sao enviadas ao servidor. Metadata e
deterministica e limitada a uma lista permitida; o servidor armazena somente
ciphertext, envelope e metadata sanitizada.

`sync-client/rootark-sync-journal.js` grava pending/seen operations com arquivo
temporario, `fsync`, rename e `fsync` do diretorio. Reabrir o journal recupera
operacoes pendentes. O journal pode ser usado pelo bridge local para registrar
callbacks de MOVE/DELETE.

Os endpoints autenticados `POST/PUT /sync/v1/objects`, `GET
/sync/v1/objects[:objectId]` e `DELETE /sync/v1/objects/:objectId` sao
server-blind, limitados a 9 MiB por requisicao (8 MiB de ciphertext), escopados
ao usuario autenticado e persistidos atomicamente em `data/sync-objects.json`.
DELETE grava um tombstone validado com revisao base, rejeitando replay, stale e
conflitos.
Ele nao e uma substituicao das rotas existentes de upload.
