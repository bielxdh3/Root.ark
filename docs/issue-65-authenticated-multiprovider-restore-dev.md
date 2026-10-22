# Issue #65: GET ciphertext multiprovedor autenticado (DEV)

Esta rota requer **opt-in explícito**, `NODE_ENV=development|test`, o
`ROOTARK_ZK1_CONTENT_CONFIG` versão **2**, witness/CAS independentes
provisionados e `ROOTARK_ZK1_MULTIPROVIDER_RESTORE_MODULE` com caminho
absoluto para um módulo JavaScript de propriedade do operador.
Esse módulo exporta uma função sem argumentos que constrói e retorna:

```js
module.exports = function provisionRestore() {
  return {
    gatewayPins: {
      pinnedInventoryPublicKey, pinnedInventorySignerKeyId,
      pinnedOwner, pinnedOwnerHead, independentInventoryFloor,
    },
    restoreInput: {
      mode: "cloud-catalog",
      request: { scope, operation, catalogReaders, readers,
        minimumMatchingProviders: 2, minimumMatchingCatalogProviders: 2 },
    },
  };
};
```

As referências acima representam os objetos do **próprio** processo do
operador, preparados usando leitores autenticados e pins independentes. O
arquivo não deve vir do usuário HTTP, do catálogo remoto ou da aplicação.
Este módulo é código com privilégio de inicialização, executado pelo Node;
se o operador não puder garantir a origem dos pins/leitores, não o configure.
Nunca inclua chaves/credenciais reais em um commit ou fixture.

O módulo **não aceita** `assertCurrentAuthorization` nem um `gateway` externo
como autoridade para este endpoint. A aplicação constrói seu próprio gateway
por requisição e faz `store.authorize` contra o witness atual, manifesto CAS
e cadeia Ed25519 completa antes e depois de recuperar as cópias.

## HTTP

`POST /zk-1/v1/multiprovider-restore/read` na sessão normal autenticada.
Exige permissão `listFiles`, cookie de sessão e `rootark_csrf` mais header
`X-CSRF-Token` (ou o bearer válido conforme política vigente). Corpo JSON:

```json
{
  "authorization": "objeto da autorização histórica GET/v1, de escopo fixo",
  "signatureBase64": "assinatura Ed25519 base64url"
}
```

Na requisição real, `authorization` é o objeto estruturado já usado por
`/zk-1/v1/content/read`, com `operation="get"`, `object_id` da operação
provisionada, `expected_object_revision` fixa, `ciphertext_digest` exato,
manifest revision/digest/epoch atuais, nonce novo de 32 bytes, emissão e
expiração de até 60 segundos. O servidor valida a assinatura contra a chave
do dispositivo **não revogado** no manifesto genuinamente assinado; o nonce
é consumido em SQLite FULL com piso anti-rollback, sob reserva witness
durante GET e egress. O estado de sessão/permissão/CSRF é revalidado no fim.

A resposta 200 leva apenas ciphertext base64url, identificadores/digest/raiz,
catálogo e provas assinadas; em falha a resposta é fechada, sem ciphertext.
Nenhuma CEK/plaintext deve passar por esse endpoint. Não há escrita do
resultado restaurado na base de arquivos, nem autorização para produção.

## Limites

- A recuperação é apenas para objeto **sem cópia local**. Quando a cópia
  protegida ainda existe, use o GET histórico normal.
- As assinaturas e provas garantem integridade e correspondência dos bytes
  nas cópias verificadas; a existência de duas namespaces declaradas pelos
  adapters ainda **não comprova independência administrativa ou durabilidade
  física** entre provedores. O retorno `remoteDurabilityProven=false` é fixo.
- A política de revogação continua dependendo de witness, CAS e histórico
  efetivamente independentes, disponíveis e atuais. Uma interrupção em
  qualquer um desses componentes bloqueia a resposta.
- A rota não faz recuperação da CEK, recuperação de plaintext no servidor,
  reconstituição de backup, cutover, merge nem alteração de dados legados.

Teste sintético: `node --test test/issue-65-full-multiprovider-http-restore.test.js`
exercita S3 SDK localhost, Drive HTTPS, WebDAV mTLS, catálogo remoto assinado,
HTTP Express com sessão real, CSRF, assinatura de dispositivo, replay,
revogação, mudança de sessão durante downloads e quorum insuficiente.
