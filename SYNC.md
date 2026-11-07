# Root.ark Sync: protocolo v2 e uploader legado

O protocolo v2 e o uploader legado de desenvolvimento sao clientes diferentes.
O `sync:init` legado **nao** provisiona as chaves ou a politica de confianca exigidas pelo v2.

No protocolo `/sync/v1`, `GET /sync/v1/objects/:objectId/history` permite ao
usuario autenticado com `listFiles` consultar as versoes cifradas ainda retidas,
inclusive depois de um DELETE logico. Outra conta, falta de permissao ou
historico inexistente nao revelam os registros. Essa rota nao descriptografa,
nao restaura automaticamente e nao altera a politica de retencao; a recuperacao
efetiva continua exigindo uma operacao autorizada do cliente. Ela nao concede
acesso aos objetos protegidos do ZK-1 por outro protocolo nem encerra a issue #67.

O cliente v2 pode listar esse historico sem modificar arquivos, operacoes
pendentes ou versoes remotas:

```powershell
node sync-client/rootark-sync-v2.js history --config <config-v2-privado> --object-id <id>
```

A consulta exige um arquivo de configuracao privado com `serverUrl`, `username`
e `token`, e permissao `listFiles` no servidor. A saida JSON inclui apenas
identificadores, caminho, revisao, dispositivo e estado `tombstone`; nao
imprime ciphertext nem chaves. O campo `signatureVerified: false` informa que
esses metadados historicos ainda nao possuem verificacao independente de
assinatura, admissao ou custodia; a consulta **nao** autoriza uma restauracao.

### Preflight de restauracao historica (#67)

O processo confiavel que ja provisiona o Sync v2 com **evidencia fisica
independente**, politica atual do dispositivo e chaves privadas pode consultar
`SyncEngine.previewHistoricalRestore(objectId, versionId)` antes de restaurar.
O mesmo preflight de `restoreHistoricalVersion` valida a versao selecionada,
o HEAD atual e a seguranca do destino local; o preview tambem valida todas
as versoes retidas com as provas de assinatura/admissao do provedor independente
e descriptografa somente em memoria para autenticar AEAD/AAD. Nao cria uma
nova operacao assinada, nao altera os arquivos do usuario, snapshot ou journal
e nao envia dados ao servidor. A saida contem apenas caminho, IDs, revisao,
tamanho, tipo de acao local e quantidade de versoes verificadas, **nunca**
plaintext/chave. Um preview bem-sucedido e **consultivo**: uma restauracao
posterior repete todas as checagens e pode falhar por mudanca de HEAD, grants
ou arquivos locais.

O preview exige que **snapshot e journal ja existam e sejam arquivos regulares**.
Inclusive a inicializacao pela CLI usa `open({ readOnly: true })`, sem a
abertura normal de escrita que poderia recriar o journal entre duas checagens.
Nao cria nem recria journal/snapshot ou `.rootark-sync.lock`. Espera a fila de
escritores do processo, recusa um lock de outro processo e compara identidade,
tamanho e tempos dos dois arquivos antes/depois da consulta; ausencia ou mudanca
intermediaria faz o preview falhar fechado. Essa checagem otimista nao reserva
o HEAD remoto nem impede futuras alteracoes por outros processos: executar
`restore` exige nova autorizacao e revalidacao independente.

O subcomando `preview --config <privado> --object-id <id> --version-id <id>`
existe para integracoes que injetem as autoridades independentes do cliente.
Na CLI isolada, sem esse provedor e os pins externos, **falha fechado**;
`--config` e a resposta de `history` nao substituem custodia verificavel.

### Plano consultivo de recuperacao de multiplos objetos (#67)

O mesmo cliente confiavel pode chamar
`SyncEngine.previewHistoricalRestorePlan([{objectId, versionId}, ...])` para
consultar **1 a 32 objetos diferentes** antes de qualquer restauracao.
Cada entrada passa pelo preflight individual de historico assinado, prova de
admissao fisica independente, HEAD atual, AEAD/AAD e destino local limpo. A
consulta inteira compartilha a verificacao de integridade de snapshot e
journal e recusa dois objetos que usem caminhos locais iguais (inclusive
diferencas de maiusculas/minusculas) ou relacao arquivo/descendente. No final,
reconsulta os HEADs e a autorizacao atual e reexamina os destinos anteriores,
para detectar alteracoes ocorridas enquanto os outros objetos eram consultados.
Um erro em qualquer objeto rejeita o plano inteiro, sem resposta parcial `ready`.

O resultado JSON inclui `readOnly:true`, `ready:true`, `atomic:false`,
`objectCount`, `localOverwriteCount` e `entries` com os IDs, revisoes, caminhos,
quantidade de versoes verificadas, digests SHA-256 dos envelopes assinados e
`localAction` de cada arquivo. O valor
`replace-clean-tracked` significa que uma restauracao posterior **substituiria
bytes locais atualmente limpos**; `create-from-deleted` exige destino ausente.
Nenhum plaintext, chave ou ciphertext e impresso, e nenhuma operacao e assinada,
enfileirada ou enviada. O plano **nao reserva** HEADs, autorizacoes ou arquivos,
nao e uma transacao de restauracao e nao prova o estado de pausa/retomada remota.

Para a integracao com autoridade externa, a entrada equivalente do CLI e:

```powershell
'[{"objectId":"objeto-1","versionId":"versao-1"},{"objectId":"objeto-2","versionId":"versao-2"}]' | node sync-client/rootark-sync-v2.js preview-plan --config <config-v2-privado> --plan-stdin
```

O `preview-plan` da CLI isolada continua **falhando fechado** sem o provedor de
custodia independente e os pins de dispositivo mantidos fora da configuracao.
A entrada JSON via stdin e limitada e validada antes de carregar credenciais.
Depois de revisar o resultado em uma integracao confiavel, cada `restore`
individual precisa de nova validacao e de commit CAS assinado; uma falha em um
objeto pode deixar restauracoes anteriores concluidas e as posteriores intactas.
O fluxo `resume` de outro dispositivo confiavel continua separado, com prova
de senha/2FA e persistencia pelo servidor. Nenhum desses previews certifica a
custodia independente de producao ou o encerramento da issue #67.

### Execucao controlada e retomada parcial de restores historicos (#67)

Uma integracao **ja autenticada e provisionada com custodia externa** pode
obter `const plan = await engine.previewHistoricalRestorePlan(requests)` e,
somente apos confirmacao explicita do usuario, chamar
`await engine.restoreHistoricalPlan(plan, {confirm: true})`. A chamada exige
1–32 objetos distintos, compara o plano original com um **preflight integral
novo** antes de qualquer mutacao e revalida a entrada imediatamente antes de
cada `restoreHistoricalVersion`. Usa a assinatura Ed25519, o CAS remoto e as
provas historicas do cliente existente. Um plano alterado ou desatualizado e
recusado antes do primeiro arquivo. A autorizacao atual e exigida em cada
operacao; o plano persistido nunca serve como concessao de acesso.
Se alguma entrada tiver `localAction: "replace-clean-tracked"`, a execucao
exige confirmacao adicional explicita `confirmCleanOverwrite: true`; o resultado
inclui `localOverwriteCount` e a acao proposta por objeto.

O progresso e mantido em arquivo local reservado
`.rootark-recovery-execution-<digest>.json`, persistido com fsync. Ele registra
somente IDs, digests de envelopes assinados e estados por objeto (`pending`,
`blocked`, `committed`, `indeterminate`); nao contem conteudo ou chaves. O
arquivo inicial e publicado somente apos gravacao e fsync de um temporario
privado completo, via hardlink **sem substituicao**. Falha/ENOSPC anterior a
essa publicacao deixa apenas temporario ignorado e preservado para exame;
nao cria progresso final parcial nem bloqueia um plano ainda nao iniciado.
Se uma queda ocorrer depois do hardlink final, mas antes do unlink do
temporario ou do fsync do diretorio, o progresso completo pode aparecer com
dois nomes para **o mesmo inode**. Na retomada sob lock exclusivo, o cliente
so regulariza esse caso ao encontrar exatamente o temporario privado gerado
com nome reconhecivel, identidade de inode/conteudo igual, `nlink=2` e JSON
com o mesmo digest/escopo do plano; a remocao desse alias recebe fsync do
diretorio no POSIX. Hardlinks desconhecidos ou multiplos aliases permanecem
bloqueados, preservados para verificacao externa.
Um arquivo final preexistente invalido continua bloqueado ate reconciliacao
externa: ele nunca e apagado, substituido ou tratado como prova de ausencia
de envio.
O retorno oferece `atomic:false`, `completed`, `remaining`, `partial`, `planDigest`
e `items` com resultados individuais. Os commits ja concluidos nao sao
reemitidos. Para continuar um plano parcialmente bloqueado depois de resolver
o problema, um cliente confiavel deve passar o **mesmo** plano:

```js
await engine.restoreHistoricalPlan(plan, {confirm: true, resume: true});
```

Antes de retomar, o cliente confirma cada sucesso por envelope assinado no
HEAD, registro duravel local do outbox, verificacao externa de admissao,
identidade da revisao-base, conteudo original autenticado, AEAD e bytes locais.
Os objetos ainda pendentes passam novamente pela verificacao completa. Se o
ultimo gate de autorizacao recusar **antes de chamar enqueue**, ou um conflito
local fizer `discardUnsent` remover duravelmente a operacao ainda nao enviada,
o progresso marca `blocked` com `neverDispatched:true`. Ao retomar exige que
o journal continue sem outbox/recibo/observacao para o ID, e que HISTORY/HEAD
assinados ainda comprovem o estado anterior, antes de qualquer nova assinatura.
Esse campo nao autoriza nada sozinho. Se a remocao/ausencia nao for comprovada,
a operacao continua indeterminada. Se o
processo caiu apos gravar a intencao assinada, houve falha de fsync, perda de
ACK ou um envio ficou pendente, esse item permanece `indeterminate`. Na
retomada, somente uma confirmacao independente do **mesmo HEAD assinado ja
admitido**, com fonte historica, bytes locais e snapshot duravel identicos,
permite recuperar o sucesso sem um segundo PUT. Na ausencia dessa prova,
a retomada **recusa novas assinaturas** ate reconciliacao explicita externa.
Isso preserva o outbox assinado e evita uma segunda restauracao
sob um estado remoto desconhecido. Uma falha em um objeto pode deixar os
anteriores concluidos: **nao existe transacao multiobjeto nem rollback global**.

Nao ha CLI standalone de execucao: ela nao dispoe da autoridade de custodia
independente exigida. O comando `resume --device-id` para liberar um dispositivo
pausado e uma operacao separada, que verifica senha/2FA no servidor. Estes
controles sao de engenharia local; nao comprovam custodia R1 de producao.

### Revisao de falso positivo e retomada de dispositivo pausado (#67)

Quando a protecao contra alteracoes destrutivas devolve `sync_burst_paused`
(HTTP 423), revise primeiro o historico e os arquivos afetados. De **outro
dispositivo confiavel** da mesma conta, o Sync v2 oferece o comando:

```powershell
node sync-client/rootark-sync-v2.js resume --config <config-v2-privado> --device-id <dispositivo-pausado> --credentials-stdin
```

`--credentials-stdin` exige um unico objeto JSON UTF-8 fornecido por fluxo
privado de entrada, `{"password":"...","code":"..."}`. `code` pode ser
omitido se a conta nao exigir TOTP; se exigir, deve ser TOTP valido ou codigo
de recuperacao ainda nao usado. Use um gerenciador confiavel para alimentar
stdin; **nao** passe senha/codigo nos argumentos, nem os coloque em scripts,
historico do PowerShell ou arquivos sincronizados. A configuracao precisa de
`serverUrl`, `username`, `token` e `deviceId` do dispositivo que solicita a
retomada. O cliente recusa auto-retomada declarada e redirects autenticados.

O servidor verifica a sessao, a permissao `upload`, a senha e o segundo fator
de maneira independente, mantendo suas protecoes contra concorrencia e replay.
A saida JSON contem apenas `protocolVersion`, `deviceId`, `paused:false` e
`wasPaused`; erros HTTP nao ecoam credenciais. A retomada nao desfaz arquivos,
nao altera historico retido nem autoriza uma versao historica como operacao nova.

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
