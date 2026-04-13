# Workflow — Verificação de segurança das dependências (MCP)

Use este arquivo como referência para disparar a verificação de dependências do projeto com as ferramentas npm do MCP Docker.

---

## Frase padrão (copie e cole no chat do Cursor)

```
Verifica as dependências deste projeto com as ferramentas npm do MCP Docker (vulnerabilidades, versões e licenças).
```

---

## Quando usar

- Antes de merge/PR que altera `package.json`
- Após `npm install` ou ao adicionar/atualizar um pacote
- Periodicamente (ex.: mensal) para revisar o estado das dependências

---

## O que o assistente fará

1. Ler `package.json` (dependencies e devDependencies)
2. Usar as tools do MCP_DOCKER (ex.: vulnerabilidades, versões mais recentes, licenças)
3. Devolver um resumo com: pacotes vulneráveis, sugestões de atualização e recomendações

**Requisito:** o servidor MCP_DOCKER deve estar ativo e conectado no Cursor.
