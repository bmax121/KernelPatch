# Guia

## Como funciona o KernelPatch

KernelPatch consiste em três componentes: kptools, kpimg e kpatch.

### [kptools](/tools/)

kptools serve aos seguintes propósitos:

- Ele pode analisar imagens do kernel sem código-fonte ou informações de símbolos e recuperar os endereços de deslocamento de símbolos arbitrários do kernel.
- Ele corrige a imagem do kernel anexando o kpimg ao final da imagem e gravando as informações necessárias nos locais predeterminados no kpimg. Finalmente, ele substitui o local de inicialização do kernel pelo endereço inicial do kpimg.

### [kpimg](/kernel/)

- kpimg é um ELF especialmente projetado.
- kpimg assume o processo de inicialização do kernel, executa todos os patches dinâmicos do kernel e exporta funcionalidades para uso do usuário por meio de chamadas do sistema.
- Se você não precisa de funcionalidades extensas ou deseja customização, você pode utilizar separadamente o código em [kernel/base](/kernel/base).

### [kpuser](/user/)

kpuser é o arquivo de cabeçalho do espaço do usuário e a biblioteca do KernelPatch. Você pode incorporar o kpuser diretamente em seu programa.
