# Backups do Root.ark

O sistema de backup protege metadados, banco SQLite local e arquivos enviados sem incluir segredos.

## Local

Backups, o lock, o histórico JSON e os temporários de restore ficam no diretório de runtime do processo:

```text
<runtime-root>/data/backups
```

Formato:

```text
rootark-backup-YYYY-MM-DD-HH-mm-ss.zip
rootark-pre-restore-YYYY-MM-DD-HH-mm-ss.zip
```

Cada arquivo inclui `backup-manifest.json`.

## Variáveis

```env
BACKUP_ENABLED=true
BACKUP_AUTO_ENABLED=true
BACKUP_TIME=03:00
BACKUP_RETENTION_DAYS=30
BACKUP_RETENTION_COUNT=10
BACKUP_INCLUDE_UPLOADS=true
BACKUP_INCLUDE_TEMP=false
BACKUP_COMPRESS=true
```

## O que entra

- O banco SQLite configurado por `DATABASE_URL`, com `-wal` e `-shm` quando existirem; ele é restaurado no mesmo caminho configurado.
- JSON antigos em `<runtime-root>/data/*.json`, se existirem.
- `<runtime-root>/uploads`, se `BACKUP_INCLUDE_UPLOADS=true`.
- metadados importantes em `<runtime-root>/data`.

## O que não entra

- `node_modules`
- `.git`
- `.env`
- credenciais AWS/GDrive
- arquivos `.key`, `.pem`, `.p12`
- `data/server-master.key`
- `data/backups`
- uploads temporários incompletos em `temp/.chunks` e `temp/.incoming`

## Backup manual

Pelo painel:

```text
Admin > Backups > Criar backup agora
```

Ou pela API:

```http
POST /backups
```

Requer admin, `manageUsers` ou `manageBackups`.

## Backup automático

Se `BACKUP_AUTO_ENABLED=true`, o servidor cria um backup diário no horário de `BACKUP_TIME`.

O último erro aparece no painel de backups via:

```http
GET /backups/latest-status
```

## Restore

Pelo painel:

1. Abra `Backups`.
2. Clique em `Restaurar`.
3. Confirme o aviso.
4. Digite exatamente `RESTORE`.

Antes da restauração, o servidor cria um backup `pre-restore`.

### Restore em implantação de instância única

Execute exatamente um processo do servidor por runtime. `ROOTARK_RESTORE_INSTANCE_COUNT` deve permanecer em `1` (padrão); o servidor encerra a inicialização para qualquer outro valor porque limites de autenticação, desafios de login e proteção contra replay de TOTP ainda são mantidos por processo. Essa variável declara a topologia e não detecta réplicas ocultas; configure o orquestrador para manter uma única réplica. O protocolo de confirmação entre várias instâncias existe no serviço de restore, mas não torna a aplicação multi-instância segura para autenticação. Não escale horizontalmente até existir estado de autenticação compartilhado e transacional.

Após restaurar, reinicie o único processo do servidor. O serviço recupera ou confirma o coordenador antes de liberar requisições. Se o processo não iniciar e a barreira permanecer ativa, preserve o coordenador e os arquivos de recuperação e siga o procedimento de recuperação documentado; não os apague manualmente.

### Proteção dos diretórios no host

Execute Root.ark com uma conta de serviço dedicada. Os diretórios de runtime usados como origem ou destino de restore — incluindo `data`, `uploads`, quarentena, extração/pre-images de backup e os diretórios-pai dos caminhos SQLite ou de outros armazenamentos configurados — devem pertencer ao domínio de confiança do serviço/operador. Nenhum usuário ou processo não confiável do host pode renomear, substituir ou gravar nesses diretórios ou em qualquer ancestral deles enquanto o servidor estiver ativo. Configure caminhos de armazenamento absolutos e protegidos por permissões do sistema operacional; não use diretórios compartilhados graváveis por usuários não confiáveis.

O restore rejeita symlinks e compara a identidade do arquivo aberto com a identidade do caminho antes de copiar bytes. Ainda assim, as APIs portáveis de caminhos do Node.js não mantêm handles de diretório para cada componente ancestral; portanto, essa verificação não elimina corridas se um ator local puder substituir um ancestral por symlink/junction durante a operação. Restrinja essa autoridade por ACL/permissões do host e pare o serviço antes de alterar os caminhos configurados.

Restore interrompido em versões anteriores pode deixar um arquivo como `runtime.json.<uuid>.restore-preimage`. O coordenador antigo não registrava esse caminho; por isso, a recuperação atual não o remove automaticamente, pois não consegue provar que seja um temporário e não dado do usuário. Verifique esse resíduo manualmente após preservar um backup; não apague arquivos apenas pelo sufixo.

Cada atualização do journal SQLite é gravada em um temporário exclusivo no mesmo diretório, sincronizada e publicada por rename atômico; temporários abandonados não substituem o journal válido. No POSIX, falhas ao sincronizar o diretório são propagadas e mantêm o restore em falha/recuperação, em vez de serem ignoradas. O Node.js não oferece sincronização portável de diretórios no Windows; a persistência contra perda súbita de energia nesse sistema continua limitada pelas garantias do sistema de arquivos e da plataforma.

O restore:

- valida o ZIP;
- valida `backup-manifest.json`;
- verifica checksum quando disponível;
- bloqueia path traversal;
- rejeita paths absolutos e symlinks;
- extrai em `<runtime-root>/data/backups/.restore-tmp`;
- restaura JSON em `<runtime-root>/data` e uploads em `<runtime-root>/uploads`;
- limpa temporários.

Se o backup tiver SQLite, reinicie o servidor após restaurar para garantir que o banco recarregue limpo.

## Auditoria

Eventos registrados:

- `backup.created`
- `backup.failed`
- `backup.deleted`
- `backup.downloaded`
- `backup.restore.started`
- `backup.restore.completed`
- `backup.restore.failed`

## Recuperação manual

Se necessário:

1. Pare o servidor.
2. Extraia um backup em uma pasta separada.
3. Se `DATABASE_URL` estiver configurada, copie `data/rootark.sqlite`, `data/rootark.sqlite-wal` e `data/rootark.sqlite-shm` para o caminho configurado e seus arquivos auxiliares. Com o caminho padrão, copie-os para `./data/rootark.sqlite*`.
4. Copie `uploads` para `./uploads`.
5. Reinicie o servidor.

Não restaure `server-master.key` via backup, pois chaves privadas não são incluídas.
