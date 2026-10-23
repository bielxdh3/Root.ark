# Issue #65: arquivo offline de keyring pelo workspace autenticado (DEV)

O workspace zk-1 normal de desenvolvimento oferece agora dois botões
**opt-in**: criar e recuperar um arquivo portátil cifrado com 1–12 objetos.
O acesso ao diálogo depende da mesma capacidade autenticada de desenvolvimento
que já protege o workspace. O arquivo é construído exclusivamente no navegador;
nenhum conteúdo, CEK ou segredo é submetido a um endpoint Root.ark.

## Criar

1. Provisionar previamente o piso local IndexedDB do proprietário através
   do fluxo existente com a chave pública raw Ed25519, seu SHA-256 SPKI
   independente, revisão/digest/época atuais assinados e grant Ed25519 do
   dispositivo **não revogado**; importar cadeia de checkpoints desde gênese.
2. Selecionar até 12 arquivos locais descartáveis, até 8 MiB somados, com
   nomes de download seguros e distintos; importar segredo do holder de
   **32 bytes** separado do arquivo, chave privada **PKCS#8 do proprietário**
   e os IDs do signer/dispositivo do checkpoint histórico.
3. Confirmar a caixa de opt-in e criar. Antes de cifrar, o navegador verifica
   correspondência da chave privada ao proprietário externamente pinado e
   revalida o grant/histórico/piso. O helper assina roots individuais e a
   cápsula integral (Ed25519) e cifra o conjunto por AES-256-GCM.
4. Salvar **separadamente** `rootark-keyring-archive.json` e
   `rootark-keyring-archive.sha256.txt`, e preservar o segredo do holder por
   canal independente. O próprio arquivo NÃO estabelece a origem do hash.

## Recuperar

Importar a mesma cadeia de trust, grant atual e pins externos, segredo de
32 bytes, arquivo `.json`, SHA-256 base64url de 32 bytes obtido por **outro
canal** e identidade do signer do proprietário. A recuperação valida todos
os roots e todo o conteúdo **antes** do primeiro download local. Hash errado,
assinatura forjada, scope trocado, grant revogado/stale ou ausência de opt-in
bloqueiam os downloads. Não há persistência IndexedDB de plaintext/CEK:
apenas o piso monotônico do proprietário é mantido. Inputs de segredo/chave,
arquivo cifrado e arquivos selecionados são limpos ao finalizar.

## Limites

- **O fluxo é offline**: a validade *online agora* da revogação e a
  independência física dos checkpoints/pins não são comprovadas pelo módulo.
  O usuário deve verificar a atualidade do owner head fora do servidor.
- O download depende de permissão do navegador para múltiplos arquivos;
  não grava dados no servidor nem os restaura no cofre remoto.
- Os downloads explícitos criam Blobs temporários em memória e os arquivos
  baixados são persistidos **somente pelo próprio navegador sob ação do
  usuário**. Nenhum dado é salvo automaticamente em localStorage/IndexedDB
  além do piso já existente. Use apenas dados descartáveis neste laboratório.
- 1–12 arquivos constituem um snapshot com IDs e metadados locais recém
  gerados, **não** inventário assinado de todos os objetos da conta nem
  prova de durabilidade, backup de produção ou cutover.

Testes: `test/issue-65-keyring-portable-archive.test.js` verifica provas
hostis; `test/issue-65-normal-browser-protected-content.test.js` exercita
o diálogo real no Edge, dupla exportação local, recuperação e recusas, além
de assegurar que PUTs legados e enrollment V2 não foram alterados.
