# Testes Realizados

## Teste 1 - Acesso HTTP Autorizado

### Objetivo

Validar que o celular autorizado consegue acessar o servidor web.

### Procedimento

1. Conectar o celular à mesma rede local.
2. Acessar o endereço IP do servidor pelo navegador.
3. Verificar o carregamento da página hospedada no Nginx.

### Resultado Esperado

A página web deve ser exibida corretamente.

### Resultado Obtido

Sucesso. O servidor respondeu corretamente e a página foi carregada.

---

## Teste 2 - Acesso SSH Autorizado

### Objetivo

Validar o acesso administrativo remoto ao servidor.

### Procedimento

1. Utilizar um cliente SSH no celular.
2. Conectar ao servidor utilizando a porta 2409.
3. Realizar autenticação com usuário válido.

### Resultado Esperado

A conexão SSH deve ser estabelecida com sucesso.

### Resultado Obtido

Sucesso. Foi possível administrar o servidor remotamente.

---

## Teste 3 - Transferência de Arquivos via SCP

### Objetivo

Validar a transferência segura de arquivos entre máquinas Linux.

### Procedimento

1. Utilizar SCP para transferir uma imagem do Kali Linux para o Arch Linux.
2. Confirmar a presença do arquivo no diretório de destino.

### Resultado Esperado

Arquivo transferido corretamente.

### Resultado Obtido

Sucesso. O arquivo foi transferido e disponibilizado pelo Nginx.

---

## Teste 4 - Funcionamento da Whitelist

### Objetivo

Validar que apenas o IP autorizado possui acesso aos serviços publicados.

### Procedimento

1. Configurar regras de whitelist para o IP do celular.
2. Permitir acesso apenas às portas 80 e 2409.

### Resultado Esperado

Somente o dispositivo autorizado deve acessar os serviços.

### Resultado Obtido

Sucesso. O acesso autorizado foi mantido conforme esperado.

---

## Teste 5 - Contadores do Firewall

### Objetivo

Validar o funcionamento dos counters do nftables.

### Procedimento

1. Acessar o servidor web.
2. Realizar conexões SSH.
3. Consultar os contadores das regras.

### Resultado Esperado

Os contadores devem registrar os pacotes processados.

### Resultado Obtido

Sucesso. Os contadores registraram os acessos realizados.

---

## Teste 6 - Logging de Pacotes Bloqueados

### Objetivo

Validar o registro de tentativas de acesso não autorizadas.

### Procedimento

1. Gerar tráfego não permitido.
2. Verificar os logs do sistema.

### Resultado Esperado

Os eventos devem ser registrados com o prefixo configurado.

### Resultado Obtido

Sucesso. Os pacotes bloqueados foram registrados pelo firewall.
