# Root.ark Sync: protocolo v2 e uploader legado

O protocolo v2 e o uploader legado de desenvolvimento sao clientes diferentes.
O `sync:init` legado **nao** provisiona as chaves ou a politica de confianca exigidas pelo v2.

## Comandos

```powershell
npm run sync:init
npm run sync:start:legacy-dev -- --once
```

Estes dois comandos se referem **somente ao uploader legado (dev opt-in)**.
`sync:init` pede URL do servidor, usuario, senha, pasta local e `folderId` de destino. A senha e usada apenas para login e nao e salva; o token Bearer e armazenado num arquivo privado, nunca numa pasta compartilhada por padrao.

O caminho padrao do legado e `%APPDATA%\Rootark\sync\config.json` no Windows e `${XDG_CONFIG_HOME:-~/.config}/Rootark/sync/config.json` em POSIX. `--config <caminho>` aceita apenas um diretorio com permissoes privadas e arquivo regular do usuario; links simbolicos, hardlinks e configuracoes legiveis por outros usuarios sao recusados. Um `.rootark-sync.json` legado antigo no diretorio atual so pode ser reutilizado pelo `sync:start:legacy-dev` se for seguro e nao contiver uma politica do v2. `sync:init` sem `--config` nao sobrescreve esse arquivo antigo.

`sync:start:legacy-dev` monitora a pasta local, ignora arquivos sensiveis/temporarios e envia arquivos novos ou alterados para `/upload`. URLs remotas exigem HTTPS; HTTP so e permitido para destinos locais aprovados. Redirects autenticados sao bloqueados.

Para o **Sync v2**, use `npm run sync:start -- --config <config-v2-privado> --once` depois do provisionamento independente da identidade e politica dos dispositivos e das chaves mantidas apenas em memoria. O v2 recusa uma configuracao sem `trustedDevicePublicKeys` e `revokedDeviceIds`; nao reutilize a configuracao do uploader legado. O arquivo v2 deve estar em pasta privada e protegido contra substituicao local.

## Opcoes

```powershell
npm run sync:init -- --server http://localhost:3000 --username usuario --folder E:\RootArkSync --folder-id root
npm run sync:start:legacy-dev -- --once
npm run sync:start:legacy-dev -- --auto-approve true
```

Use `ROOTARK_SYNC_PASSWORD` para renovar token expirado sem salvar senha:

```powershell
$env:ROOTARK_SYNC_PASSWORD="sua-senha"
npm run sync:start:legacy-dev
```

## Estado local

No uploader legado, o estado fica **em arquivo privado ao lado da configuracao bearer**,
e nunca dentro da pasta sincronizada (que pode ser compartilhada). O nome
`.rootark-sync-state-<sha256>.json` vincula o cache a pasta local, URL do servidor,
usuario, `folderId`, dispositivo e epoca da chave. Alterar o destino exige nova
verificacao e nao reutiliza marcadores `uploaded` de outra conta/pasta.

O arquivo historico abaixo, se existir **na pasta sincronizada**, e preservado
exatamente como encontrado, mas **nao e importado** nem atualizado:

```text
.rootark-sync-state.json
```

Era um cache sem autenticacao; importar `uploaded` permitiria a outro usuario
que escreva na pasta impedir uploads reais. Na primeira execucao com o novo
estado privado, arquivos sao reenviados para o servidor para reconstruir o
cache. Isso pode criar novas versoes de arquivos ja enviados; o estado antigo
fica disponivel para recuperacao manual, sem sobrescrita ou exclusao automatica.

O estado privado registra caminho relativo, tamanho, `mtime`, hash SHA-256,
status do ultimo upload e nome remoto. Leituras sao limitadas a 16 MiB;
estados maiores ou invalidos sao recusados para evitar aceitar corrupcao como
confirmacao de upload. Nao armazena senha nem bearer token.
Um arquivo `.lock` ao lado desse estado impede **duas instancias** de usar
simultaneamente a mesma identidade: a segunda falha imediatamente com
`SYNC_STATE_LOCK_HELD` antes de ler o cache ou iniciar uploads. O lock e
criado exclusivamente com permissoes privadas e liberado em encerramentos
normais do processo. Apos encerramento forcado (como SIGKILL/queda de energia),
um lock antigo pode permanecer; **nao e removido automaticamente**, porque
checar apenas PID pode sofrer reutilizacao e apagar um lock valido. Para
recuperar, verifique que nenhuma instancia de sync dessa identidade esteja
ativa e somente entao remova manualmente o arquivo `.lock` indicado no erro.
Nunca remova o arquivo de estado ou a configuracao bearer para resolver lock.
Toda nova varredura verifica um snapshot local estavel e seu SHA-256 antes de
reutilizar `uploaded`: arquivos de mesmo tamanho com `mtime` restaurado nao
podem ser ignorados por uma pasta compartilhada. Esse cuidado aumenta o custo
de leitura durante as varreduras periodicas.

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

## Sincronizacao seletiva: pastas excluidas (issue #66)

O arquivo de configuracao do `rootark-sync-v2` (`.rootark-sync.json`) aceita `selectedPaths` (lista de escopo) e `excludedPaths` (lista de prefixos de pasta a excluir, por dispositivo). Cada entrada e validada com `validatePortableRelativePath`: caminho relativo, sem `..`, barras invertidas, caminhos absolutos, nomes reservados do Windows ou arquivos internos do sync.

Comportamento de `excludedPaths`:

- Arquivos sob um prefixo excluido nao sao baixados no pull e nao sao enviados nem apagados remotamente no push.
- Ao excluir uma pasta, copias locais limpas sao removidas com `_evictLocal`: o objeto remoto permanece, sem tombstone. Copias com alteracao local pendente sao mantidas e reportadas em `summary.excluded.kept`.
- Arquivo excluido sem copia local vira registro remoto (`reason: "excluded"`) e nenhum delete e enviado.
- Ao reincluir a pasta, os arquivos liberados sao baixados no proximo sync. Arquivos apenas despejados (`reason: "evicted"`) continuam remotos ate `materializeRemote(caminho)`.
- A lista aplicada fica persistida no indice do sync (`excludedPaths`) e a reconciliacao so roda quando a lista muda.
- Falha transitoria de despejo (`EBUSY`, `EPERM`, `EAGAIN`, por exemplo arquivo aberto no Windows) e registrada em `pendingEvictions` no indice e tentada de novo nos syncs seguintes, no maximo 3 vezes. Depois disso o item aparece em `summary.excluded.failed` sem novas tentativas. Arquivos com alteracao local nunca entram nessa fila; nenhuma tentativa envia delete remoto.

Limitacoes: nao ha comando CLI dedicado (a configuracao e o ponto de controle); nao ha placeholder nativo nem Files On-Demand; pastas vazias excluidas nao sao removidas localmente; metadados remotos ainda sao listados completos antes do filtro local.

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
