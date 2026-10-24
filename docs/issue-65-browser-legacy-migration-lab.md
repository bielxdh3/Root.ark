# Issue #65 — migração manual legada para ciphertext ZK (laboratório)

Escopo: cópia **não destrutiva**, iniciada pelo usuário no painel autenticado de
desenvolvimento (`Arquivo zk-1`), de um arquivo legível no antigo `GET /files/:name`
para um objeto ZK novo em `/zk-1/v1/content/put`. Limite: 2 MiB de plaintext.
Somente instâncias descartáveis de desenvolvimento/teste devem habilitar a
capacidade `/zk-1/v1/workspace-capability`.

## Fronteiras e execução

1. Provisionar offline a chave pública Ed25519 do proprietário, hash da chave,
   hash do SPKI, revisão/epoch/digest atuais de fonte **fora do servidor**,
   grant do dispositivo assinado, cadeia histórica assinada desde a gênese,
   par de chaves do dispositivo e piso local. A validação ocorre **antes** do
   primeiro GET legado e é repetida em cada tentativa de retomada.
2. Selecionar nome/pasta legados, marcar explicitamente `Solicito ... cópia` e
   importar uma **CEK aleatória de 32 bytes conservada fora do servidor**.
   `Copiar / retomar GET` escolhe IDs de objeto/versão quando vazios; copiar
   esses IDs e guardar a CEK para uma nova sessão do navegador.
3. O navegador busca plaintext pelo **endpoint legado**, cifra com AES-256-GCM
   e AAD do objeto ZK e grava somente ciphertext, hashes de consistência e
   IDs no IndexedDB. O journal pede transação de durabilidade `strict` e só
   emite PUT depois que a transação termina. A autoridade de PUT/GET inclui
   assinatura do dispositivo e revisão/epoch do manifesto.
4. O estado `uncertain` é gravado **antes** do PUT. Se o PUT ou sua resposta
   falhar, o próximo acionamento realiza apenas GET histórico assinado da
   revisão 1, comparando digest, raiz Merkle, AEAD e digest do plaintext.
   Nunca reenvia automaticamente um PUT ambíguo. Reconfere bytes, nome e
   tipo MIME lendo novamente a origem legada. Fonte modificada = recusa.
5. O resultado do GET é `awaiting-independent-owner-checkpoint`. Fora do
   servidor, o proprietário deve assinar um checkpoint da raiz ciphertext
   com escopo, objeto, revisão, epoch e digest do mesmo manifesto. Importar
   esse arquivo e acionar `Verificar checkpoint assinado` provoca novo GET
   histórico, revalidação da origem e verificação de assinatura/histórico.
   **Guardar esse checkpoint e a cadeia atual fora do servidor** para futuras
   verificações. A interface não gera/assina tal prova como se fosse externa.

Em qualquer fase, `canDeleteLegacy=false` e `authorizesCutover=false`.
Nenhum ramo de migração chama DELETE no legado nem altera referências atuais.
Se perder a CEK, o jornal, o grant ou os IDs, a cópia fica bloqueada; o
arquivo antigo continua sendo a origem preservada. Após perda de um journal
`uncertain`, não há rePUT automatizado sem uma nova autoridade/identidade.

## Exposição de metadados e garantias limitadas

- O **servidor antigo já conhece o plaintext** da rota legada. O novo fluxo
  ZK não envia plaintext, CEK, chave privada ou envelope de recuperação ao
  servidor protegido. A leitura do legado continua sujeita à autenticação,
  permissão e logs existentes do modo antigo.
- O servidor ZK observa escopo/identificadores do objeto, epoch, tamanho
  ciphertext, horário e padrão de acessos. O envelope cifrado também contém
  metadados estruturais do objeto. O IndexedDB local guarda ciphertext,
  raiz, digest do conteúdo original, digest de nome/MIME e hash de vínculo
  da origem; esses hashes podem revelar conteúdo/nomes previsíveis a quem já
  consegue ler o perfil do navegador.
- A assinatura histórica demonstra a relação criptográfica entre raiz,
  escopo e revisão, **não** durabilidade no provedor externo, fsync do servidor,
  unanimidade de witness/CAS, independência do canal em que o usuário obteve
  o pin, ausência de rollback do perfil inteiro ou revogação futura.
- Não existe migração de versões, pastas, ACLs, lixeira, links, backups, sync,
  multi-host ou troca autoritativa de referências neste marco. Nenhum
  procedimento de produção é autorizado.

## Validação sintética

`node --test test/issue-65-browser-legacy-resumable-migration-http.test.js`
testa HTTP localhost real, IndexedDB transacional descartável, grant/raiz
assinados, journal reaberto, ACK perdido, PUT não entregue, GET corrompido,
replay, mutação da origem e do MIME. A suíte
`test/issue-65-normal-browser-protected-content.test.js` inclui o painel
autenticado no Edge real sob CSP, sessão/cookie/CSRF, opt-in, cópia e
retomada sem novo PUT.
