# Módulo KernelPatch

## O que é o Módulo KernelPatch (KPM)

**KPM é um arquivo ELF que pode ser carregado e executado dentro do espaço do kernel pelo KernelPatch.**

## Como escrever um KPM

Aqui estão alguns exemplos que você pode usar para entender rapidamente.

1. Um simples hello world via KPM: [hello-world](/kpm-demo/hello)
2. Como fazer inline-hook da função do kernel via KPM: [inline-hook](/kpm-demo/inlinehook)
3. Como conectar uma chamada do sistema via KPM: [syscall-hook](/kpm-demo/syscallhook)

### Funcionando sem árvore de origem do kernel

### Funcionando com a árvore de origem do kernel
