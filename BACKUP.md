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

### Restore em múltiplas instâncias

Configure `ROOTARK_RESTORE_INSTANCE_COUNT` com a quantidade total de processos do servidor que compartilham o mesmo runtime e o mesmo coordenador de restore. O padrão é `1`; valores aceitos vão de `1` a `128`. Para mais de uma instância, defina também `ROOTARK_INSTANCE_ID` com um identificador estável e único por processo lógico. Mantenha esse identificador igual quando a mesma instância reiniciar; processos diferentes não podem compartilhar o mesmo valor. Em implantação de instância única, o ID pode ser omitido.

Depois que o restore terminar:

1. Pare todas as instâncias que compartilham esse runtime.
2. Mantenha a mesma contagem configurada e reinicie cada instância com seu próprio `ROOTARK_INSTANCE_ID`.
3. Cada instância confirma o restore somente depois que seu listener HTTP estiver vinculado. Iniciar duas vezes com o mesmo ID conta como uma única confirmação.
4. O coordenador e as cópias de recuperação são removidos depois que todas as instâncias distintas confirmarem. Se alguma confirmação faltar, a barreira de restore permanece ativa; confira contagem e IDs e reinicie a instância ausente. Não apague manualmente o coordenador nem os arquivos de confirmação.

Todas as instâncias precisam enxergar o mesmo runtime persistente para compartilhar o coordenador e as confirmações. O mecanismo mantém uma barreira local de recuperação e não coordena restauração entre armazenamentos de runtime independentes.

Restore interrompido em versões anteriores pode deixar um arquivo como `runtime.json.<uuid>.restore-preimage`. O coordenador antigo não registrava esse caminho; por isso, a recuperação atual não o remove automaticamente, pois não consegue provar que seja um temporário e não dado do usuário. Verifique esse resíduo manualmente após preservar um backup; não apague arquivos apenas pelo sufixo.

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
