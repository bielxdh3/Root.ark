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
O uploader legado envia apenas o **nome base** ao folder remoto, sem preservar
subpastas. Por isso, se duas subpastas contiverem arquivos com o mesmo nome
(inclusive diferencas somente de caixa), a varredura falha com
`SYNC_REMOTE_BASENAME_COLLISION` antes de enviar dados. Separe os destinos ou
renomeie os arquivos para evitar sobrescrita sem sinalizacao.

Para o **Sync v2**, use `npm run sync:start -- --config <config-v2-privado> --once` depois do provisionamento independente da identidade e politica dos dispositivos e das chaves mantidas apenas em memoria. O v2 recusa uma configuracao sem `trustedDevicePublicKeys` e `revokedDeviceIds`; nao reutilize a configuracao do uploader legado. O arquivo v2 deve estar em pasta privada e protegido contra substituicao local.

### Inventario remoto paginado (issue #66, parcial)

Clientes v2 autenticados com permissao `listFiles` podem consultar
`GET /sync/v1/objects?view=metadata&limit=64` e seguir `nextCursor`
usando `&cursor=<cursor>`. As paginas tem no maximo 64 registros e 128 KiB
de resposta JSON. Cada registro inclui identificadores, revisao, operacao,
metadados e estado de exclusao, mas omite ciphertext, nonce, tag e AAD.
`GET /sync/v1/objects` e `GET /sync/v1/objects/:objectId` continuam
retornando os envelopes completos para clientes existentes.

O cliente pode usar `adapter.listInventory({ limit, cursor })` ou
`engine.browseRemoteInventory({ limit, cursor })` para navegar sem baixar
conteudo cifrado. `selectedOnDevice` e apenas a politica local dessa
instancia do engine; o inventario e **informativo, sem verificacao de assinatura**.
Antes de materializar, reconciliar ou admitir operacoes protegidas, o cliente
continua usando a leitura completa por `objectId` com validacao independente
de assinatura, dispositivo e revogacao. O fluxo normal `syncOnce` preserva
essas garantias e ainda utiliza o LIST completo.

Os cursores sao vinculados ao conjunto atual de metadados da conta autenticada;
se o conjunto mudar durante a navegacao, a proxima pagina retorna HTTP 409 e
o cliente deve recomeçar pela primeira pagina. Cursor e limite invalidos
retornam HTTP 400. Esta etapa ainda nao implementa placeholder nativo,
eviction contra escritor externo com arquivo aberto ou a migracao automatica
do `syncOnce` para inventarios por pagina.

Para evitar reler o arquivo de objetos inteiro em cada pagina, o servidor
guarda em LRU **ate dois indices positivos de contas por instancia**, com
limite individual de **32 MiB** e total de **64 MiB de registros JSON
serializados**, sem manter ciphertext nesse cache. Alternar paginas entre
duas contas nao exige revalidacao completa de todo o JSON a cada acesso.
Uma terceira conta pode expulsar a menos recentemente usada; essa conta
precisara de nova leitura na proxima consulta.
O teto mede os registros serializados, **nao o RSS total do processo**:
um volume maior de objetos ou metadados pode atingir o teto. Se o indice
da conta exceder 32 MiB, a rota retorna **HTTP 507** com codigo estavel
`metadata_index_too_large`, em vez de voltar a reler o JSON a cada pagina.
O servidor memoriza apenas um marcador de excesso por conta e revisao
duravel, evitando reprocessamento em tentativas subsequentes.
Os marcadores de excesso ficam num LRU separado, com no maximo
**32 contas por instancia**: a consulta de uma conta pequena nao
descarta o marcador de uma conta grande. Uma conta evictada do LRU
pode exigir uma nova validacao integral quando consultar novamente.
Cada requisicao confere o lock
do escritor, a politica de armazenamento privado quando aplicavel e a
identidade duravel do arquivo (dispositivo, inode, tamanho, mtime e ctime
com precisao de nanossegundos). Escritas atomicas de outro processo
invalidam o indice antes da pagina seguinte; o cursor antigo recebe 409.
O limite e por **tamanho do indice**, nao por numero fixo de arquivos:
bibliotecas que o excedam precisam de um mecanismo de indexacao separado
antes de poderem usar esta API paginada. As rotas legadas nao mudam.

Benchmark reproduzivel local, Windows Node 24.14.1, 10 mil operacoes
cifradas v2 com historico de uma versao cada (78,29 MiB em JSON):
no baseline as primeiras 10 paginas levaram 23.595 ms; com o indice,
as 157 paginas dos 10 mil itens levaram 2.625 ms no total (primeira
pagina 2.337 ms, 156 paginas seguintes 288 ms). O primeiro carregamento
ainda precisa validar o estado completo; nao e um indice persistido ou
uma API de buscas em plaintext no servidor.

Teste adicional com **10 mil objetos** com metadados longos
(nome e content-type de 500 caracteres, caminho de quase 500 caracteres
e parentId de 160): estado cifrado com historico de 149,62 MiB,
indice serializado de 20,50 MiB. Todas as 167 paginas, limitadas por
bytes, retornaram em 4.288 ms: primeira 3.586 ms, demais 702 ms.
Uma regressao com teto artificialmente baixo garante que o estouro
retorne 507, sem repetir a leitura pesada, e que uma escrita externa
invalide o marcador de excesso. Ela tambem testa a sequencia
conta A grande (507), conta A novamente (507), conta B pequena (200),
conta A novamente (507): B nao deve causar nova leitura da conta A.

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

No uploader legado, o estado fica **em uma pasta privada do usuario do sistema**
(`~/.rootark/sync/private-state`), independentemente do caminho da configuracao
bearer, e nunca dentro da pasta sincronizada (que pode ser compartilhada). O nome
`.rootark-sync-state-<sha256>.json` vincula o cache a URL do servidor,
usuario e `folderId` remoto. Duas configuracoes que enviam para esse mesmo
destino compartilham a trava e o cache, mesmo que mudem pasta local,
`deviceId` ou `keyEpoch`, pois esses campos nao distinguem gravacoes no
endpoint de upload legado. Alterar servidor, usuario ou pasta remota exige
nova verificacao; o cache nunca autoriza uploads a outro destino.
A pasta interna `.rootark/` e ignorada por padrao nas varreduras, inclusive
quando a pasta local escolhida abrange o diretorio pessoal do usuario.

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
Como o uploader legado envia apenas o nome-base ao servidor, o estado privado
tambem registra a autoridade duravel desse nome (raiz local + caminho relativo)
sob o mesmo lock da identidade remota. Configuracoes com a mesma conta/pasta
remota podem sincronizar nomes-base diferentes, mas a segunda raiz nao pode
assumir `same.txt` que ja foi reservado pela primeira: a tentativa falha com
`SYNC_REMOTE_BASENAME_AUTHORITY_CONFLICT` **antes do POST**. Marcadores antigos
sem origem verificavel continuam intactos, mas sao bloqueados com
`SYNC_REMOTE_BASENAME_AUTHORITY_UNVERIFIED` ate reconciliacao explicita;
jamais sao apropriados silenciosamente pela primeira configuracao a executar.
Somente reservas lidas do estado privado validado ou gravadas com sucesso
podem autorizar uploads: uma falha transitoria no `fsync` exige repetir a
gravacao antes de um novo POST, mesmo que a reserva continue na memoria. As
origens sao comparadas com maiusculas e minusculas preservadas, inclusive no
Windows (o NTFS permite diretorios sensiveis a caixa). Estados anteriores que
registraram a raiz toda em minusculas podem causar bloqueio conservador de
proveniencia e devem ser reconciliados manualmente, sem troca automatica de dono.
O cliente exige, antes de cada POST, que o servidor autenticado confirme
`GET /legacy-sync/capabilities` com `strictFilename: true`. Servidores antigos
ou incapazes de confirmar a garantia sao recusados **antes de enviar bytes**.
O envio usa o metodo distinto `PUT /upload` com o campo multipart
`rootarkSyncStrictFilename=true`: um servidor antigo nao tem essa rota e
recusa sem mutar arquivos, mesmo se o GET de capacidade atingiu outro no de
um balanceador. Sob o lock da pasta remota,
o servidor recusa com HTTP 409 qualquer nome alterado por truncamento, troca
de caracteres ou sufixo automatico por conflito pendente, preservando uploads
normais sem essa opcao. O cliente tambem recusa antes do POST nomes-base com
mais de 30 unidades UTF-16, dois-pontos, barra invertida ou caracteres de
controle, mesmo que a maquina local permita esses nomes. Assim, dois caminhos
locais nao podem adquirir direitos sobre um nome remoto diferente daquele
reservado; falhas apos tentativa de POST permanecem conservadoras e podem
exigir verificacao manual de quiescencia e do lock.
O estado e seu lock ficam numa unica pasta privada por usuario do sistema,
independentemente do caminho `--config`. Duas configuracoes privadas que
apontem para a mesma pasta local e destino remoto compartilham a identidade,
o cache e a exclusividade; nao podem forjar confirmacoes separadas.
Um arquivo `.lock` ao lado desse estado impede **duas instancias** de usar
simultaneamente a mesma identidade: a segunda falha imediatamente com
`SYNC_STATE_LOCK_HELD` antes de ler o cache ou iniciar uploads. O lock e
criado exclusivamente com permissoes privadas e liberado em encerramentos
normais do processo. Apos encerramento forcado (como SIGKILL/queda de energia),
um lock antigo pode permanecer; **nao e removido automaticamente**, porque
checar apenas PID pode sofrer reutilizacao e apagar um lock valido. Para
recuperar, verifique que nenhuma instancia de sync dessa identidade esteja
ativa e somente entao remova manualmente o arquivo `.lock` indicado no erro.
Se Ctrl+C ou outra terminacao interromper um upload em andamento, o lock e
deliberadamente preservado: o servidor ainda pode concluir a gravacao mesmo
apos a desconexao do cliente. Antes da recuperacao manual, verifique tambem
que nao ha gravacoes remotas antigas pendentes.
Uma falha de rede depois que um POST de upload pode ter sido enviado tambem
preserva o lock, mesmo que o processo termine normalmente: a falta de resposta
nao comprova que o servidor rejeitou a gravacao. Confirmar a ausencia de
operacoes remotas pendentes e obrigatorio antes de remover o lock manualmente.
O cliente em execucao tambem interrompe novos uploads quando esse resultado
fica incerto; a trava nao protege apenas o encerramento do processo.
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
