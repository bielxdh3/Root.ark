# Root.ark #65 Packet B — laboratório local de viabilidade

## Veredito

**`MOCK_ONLY` — `CONDITIONAL` para continuar a pesquisa de viabilidade.** O modelo sintético exercita alguns contratos de estado e ordenação, mas não executa SQL nem PostgreSQL. Nenhum resultado autoriza escolha de provedor, integração com o produto, compatibilidade de protocolo ou uso em produção.

## Fonte e escopo

- Worktree autorizado: `E:\servidor\.worktrees\zk-dual-recovery-20261019`.
- Branch: `cdx/rootark-dual-recovery-20261019`.
- HEAD inicial e final: `eb58557ad2f5641bb8dcca8597fa6e04e831e7d2` (sem commit local).
- Parent verificado: `ad2373b2a71feec6bb201f627038d93d12196047`.
- Estado inicial: limpo. Estado final: quatro arquivos novos e não rastreados, todos restritos ao laboratório e a este relatório. Nenhum arquivo de runtime do produto foi alterado.
- A instrução global, o `AGENTS.md` do worktree, as decisões e especificações #65 aplicáveis, Ponytail e as instruções Superpowers selecionadas foram lidos antes da implementação. UI-UX-PRO-MAX: **N/A**, pois o trabalho é de backend/teste e não inclui interface.
- A consulta obrigatória ao AI Memory foi feita para `bielxdh3/root.ark`; os resultados aplicáveis foram resumos de sessões, sem página mantida de decisão para Packet B. Nenhuma memória histórica foi tratada como instrução.

## Arquivos criados

- `lab/issue-65-packet-b/mock-packet-b.js` — ledger CAS e autoridade de gate sintéticos, em memória.
- `lab/issue-65-packet-b/mock-packet-b.test.js` — testes focados dos contratos simulados.
- `lab/issue-65-packet-b/README.md` — comando de repetição e limites do modelo.
- `docs/validation/2026-10-20-rootark-issue-65-packet-b-local-lab-report.md` — este relatório consolidado.

## Ambiente e modo

- Windows: Node `v24.14.1`; npm `11.11.0`.
- WSL Ubuntu: Node `v22.22.1`.
- `psql`, `postgres`, `initdb` e `pg_ctl` não estão disponíveis no Windows nem no WSL. Não instalei ferramentas ou dependências.
- O Docker CLI `29.6.2` está instalado, mas o daemon Linux não está acessível pelo pipe local; a disponibilidade de imagens não pôde ser enumerada. No WSL, `docker` resolve para o CLI do Windows.
- PostgreSQL: **`POSTGRES_NOT_AVAILABLE_WITHIN_APPROVED_SCOPE`**. Gate `LOCAL_POSTGRES`: **`NOT_RUN`**. Nenhum cluster, container, porta, driver ou banco foi criado ou usado.
- O modelo usa apenas APIs internas do Node. Não há SQL, nível de isolamento PostgreSQL, lock distribuído ou medição de desempenho neste experimento.

## Modelo executado

O `MockCasLedger` separa snapshots pela tupla sintética `account_id + compartment_id + keyring_id`. Uma fila de promessas serializa mutações dentro de um único processo; cada operação altera uma cópia e publica o estado somente no commit simulado. Falha injetada antes da publicação descarta a cópia. O cenário de ACK perdido lança erro depois de publicar o commit simulado; a repetição com o mesmo ID e digest devolve o mesmo resultado.

O `MockGateAuthority` emite permissões de uso único vinculadas a operação, efeito e geração. O journal em memória aceita chunks em ordem enquanto o gate está aberto. `quiesce` incrementa a geração, bloqueia novos usos e solicita parada dos efeitos ativos; o selo local exige ACK simulado para todos esses efeitos.

Esses mecanismos são código de referência **somente em memória**. A fila não simula concorrência entre processos. O journal não escreve storage nem envia egress. O ACK é um valor do teste, não evidência externa de parada. Não há witness independente neste novo modelo.

## Matriz de cenários

| Cenário | Modo e resultado | Evidência e limite |
|---|---|---|
| Compare-and-append concorrente e conflito de head | `MOCK_ONLY — PASS` | Teste existente `concurrentWritersHaveOneWinner`; somente um writer simulado vence. Não prova linearizabilidade entre processos ou instâncias PostgreSQL. |
| Isolamento de escopo | `MOCK_ONLY — PASS` | Novo teste mantém head separado ao variar account, compartment ou keyring sintético. Não prova isolamento de banco, autorização ou controles de acesso. |
| Atomicidade sob rollback injetado | `MOCK_ONLY — PASS` | Falha após alterar a cópia do transition ou do fence deixa o snapshot publicado inalterado. Não é rollback de transação PostgreSQL. |
| ACK perdido, retry e idempotência | `MOCK_ONLY — PASS` | Commit simulado seguido de ACK perdido retorna o mesmo resultado no retry, sem duplicar transition; teste existente rejeita ID/digest conflitante. Não transforma ausência de resposta real em prova de rollback. |
| Exclusão entre commit e no-commit | `MOCK_ONLY — PASS` | Duas ordens determinísticas da fila simulam commit primeiro e fence primeiro; só um terminal vence. O modelo do laboratório não produz prova final assinada. |
| Janela de expiração e skew | `MOCK_ONLY — PASS` | Modelo existente usa relógio controlado: bloqueia em `expiresAt + 29` e permite o ramo simulado em `expiresAt + 30`, condicionado a head/tombstone/resultados exatos. Isso não substitui prova v1 ou relógio distribuído. |
| Restart, restore e witness indisponível | `MOCK_ONLY — PASS` | Testes existentes preservam gate pendente após restart/restore e falham fechados durante indisponibilidade simulada. Tudo compartilha estado de teste em uma máquina. |
| Split view/equivocação por witness independente | `BLOCKED` | Não há segundo operador, ledger externo ou modelo de implantação neste escopo. Witness independente não foi demonstrado. |
| Permissão de gate, geração e chunk após quiesce | `MOCK_ONLY — PASS` | Novo teste verifica escopo, uso único, aumento de geração, bloqueio de chunk e consumo após quiesce; selo espera ACK simulado de todos os efeitos ativos. Não demonstra parada de worker nem fence físico de storage/egress. |
| Capacidade e manifesto máximo | `MOCK_ONLY — PASS` | Teste existente cobre aviso de 75%, limites de histórico/entrada e manifesto máximo serializado de `3,284,324` bytes. Não demonstra recuperação de produção sob saturação. |
| PostgreSQL, SQL, locks, contenção e restart de servidor | `NOT_RUN` | Runtime PostgreSQL e daemon Docker indisponíveis dentro do perímetro aprovado. Nenhuma inferência sobre MVCC, constraints, advisory locks, durabilidade ou recuperação do servidor. |
| Browser, custody de chave e frescor online implantado | `NOT_RUN` | Nenhum fluxo de browser, cliente, deployment ou autoridade online foi executado. |

## Execução e resultados

RED → GREEN focado:

- RED: `node --test lab/issue-65-packet-b/mock-packet-b.test.js` — exit `1`; as cinco provas pararam nas asserções esperadas de exportação ausente (`MockCasLedger` / `MockGateAuthority`), sem erro de carregamento do runner.
- GREEN inicial do laboratório: mesmo comando após implementação — exit `0`, `7/7` asserções/subtestes passaram. Depois, o teste de escopo foi refinado para cobrir separadamente os três componentes da tupla.

Bateria #65 delimitada mais laboratório:

- WSL Node `v22.22.1`: `node --test lab/issue-65-packet-b/mock-packet-b.test.js test/issue-65-*.test.js` — exit `0`, `118` testes passaram, `0` falharam.
- Windows Node `v24.14.1`: `node --test --test-reporter=tap` com o laboratório e os 13 arquivos `test/issue-65-*.test.js` — exit `0`, `118` passaram, `0` falharam.
- `npm run validate:syntax` — exit `0`, `235` arquivos JavaScript verificados, `0` falhas.
- `npm run validate:artifacts` — exit `0`.
- `git diff --check` — exit `0`; varredura de whitespace dos arquivos novos também não encontrou linhas com espaços finais.

Os testes #65 executados incluíram keyring/crypto, autorização, recuperação por pacote, KDF, compatibilidade, history/capacity, state model e políticas/offline/capability web. Nenhum teste amplo fora do escopo #65 foi executado.

## Revisão, segurança e limpeza

Foi feita uma revisão interna única do modelo e das asserções: publicação após clone, caminho de rollback, ordenação commit/fence, escopo de idempotência, uso único do permit, aumento de geração, bloqueio pós-quiesce e ACK de todos os efeitos ativos. Esta é **auto-revisão**, não auditoria independente; a revisão externa consolidada ainda está pendente.

Não foram usados serviços externos, credenciais, dados de usuário, URLs de produto, containers, clusters, drivers ou chaves reais. Não houve processos, volumes, portas ou arquivos temporários do laboratório para limpar. O guard de artefatos terminou sem apontar artefatos runtime protegidos.

Limites ainda relevantes: `REAL_PROVIDER_NOT_PROVEN`; `INDEPENDENT_OPERATORS_NOT_PROVEN`; `BROWSER_NOT_RUN`; `WIRE_V1_BLOCKED`. Os literais `type` de status/reservation/cancellation seguem sem decisão. Não há encoder/signatário compatível v1. Não foi demonstrado HA, failover, latência, custo, egress físico, custody de chave no browser ou frescor online em deployment.

## Reexecução e próximo passo

No worktree autorizado e com Node 22 ou superior, rode em Bash/WSL:

```sh
node --test lab/issue-65-packet-b/mock-packet-b.test.js test/issue-65-*.test.js
```

Resultado geral continua `MOCK_ONLY — CONDITIONAL` para pesquisa futura. Após a revisão independente solicitada pelo owner, a próxima decisão é se haverá um runtime PostgreSQL local já instalado e isolável, dentro do mesmo perímetro sem instalação, para testar as primitivas reais. Esta decisão não foi tomada nem executada.
